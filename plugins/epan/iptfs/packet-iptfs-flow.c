/* packet-iptfs-flow.c
 * Routines for iptfs dissection of inner packets.
 * Copyright (c) 2020, LabN Consulting, L.L.C
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * January 20 2020, Christian Hopps <chopps@gmail.com>
 */

#include <config.h>
#include <epan/exceptions.h>
#include <epan/expert.h> /* Include only as needed */
#include <epan/ipproto.h>
#include <epan/packet.h> /* Should be first Wireshark include (other than config.h) */
#include <epan/wmem/wmem.h>
#include <stdio.h>

#ifndef UNUSED
#define UNUSED(x) __attribute__((unused)) x
#endif

extern int hf_iptfs_cont_from;

static dissector_table_t ip_dissector_table;
static wmem_map_t *sa_map;

// multisegment_pdus=wmem_tree_new(wmem_file_scope());

#include "epan/tvbuff-int.h"

static tvbuff_t *
get_esp_tvb(tvbuff_t *tvb, packet_info *pinfo)
{
    /* get_data_source_tvb_by_name(pinfo, "Frame") has bug use when fixed */
    for (GSList *e = pinfo->data_src; e; e = e->next) {
        tvbuff_t *esptvb = get_data_source_tvb((struct data_source *)e->data);
        for (; esptvb->next; esptvb = esptvb->next)
            /* look for when our oriignal tsb is the next one
             * (decrypted) the current one should be ESP prior to
             * decrypt copy. */
            if (esptvb->next->ds_tvb == tvb->ds_tvb)
                return esptvb;
    }
    return NULL;
}

struct key {
    address src;
    address dst;
    guint32 spi;
};

typedef struct iptfs_frag_data {
    guint32 frame_num;
    guint32 seq;
    guint32 last_append_seq;  /* for start frag, the last appended seq */
    guint8 all_frag : 1;      /* frame is all a partial fragment */
    guint8 all_pad : 1;       /* frame is all pad */
    guint8 bad_chain : 1;     /* If we know that the chain is bad */
    guint8 complete : 1;      /* If the first frag comp is finalized */
    guint8 proto;             /* proto of first frag */
    guint8 len_offset;        /* offset of length in real data */
    tvbuff_t *start_frag_tvb; /* For reconstructing - start and all frag */
    tvbuff_t *end_frag_tvb;   /* For reconstructing - end (not excl.) frag */
    tvbuff_t *tvb_comp;       /* For reconstructing - only start frag */
} iptfs_frag_data_t;

typedef struct iptfs_sa_data {
    struct key key;
    wmem_tree_t *first_frags; /* unfinished first fragments */
    wmem_map_t *frames;       /* All frames by sequence number */
    iptfs_frag_data_t *frag;  /* Currently active fragment data */
    guint32 seq;              /* Currently dissecting seq */
    guint32 largest_seq;      /* largest dissected sequence */
} iptfs_sa_data_t;

#if 0
static int
key_cmp_ins(void *_a, void *_b)
{
    struct key *a = (struct key *)_a, *b = (struct key *)_b;
    int cmp;
    if ((cmp = cmp_address(&a->src, &b->src)))
        return cmp;
    else if ((cmp = cmp_address(&a->dst, &b->dst)))
        return cmp;
    else if (a->spi < b->spi)
        return -1;
    else if (a->spi > b->spi)
        return 1;
    else
        return 0;
}
#endif

static guint
key_hash(gconstpointer _key)
{
    const struct key *key = (const struct key *)_key;
    guint hash_val = key->spi;
    hash_val = add_address_to_hash(hash_val, &key->src);
    return add_address_to_hash(hash_val, &key->dst);
}

static gboolean
key_eq(gconstpointer _a, gconstpointer _b)
{
    const iptfs_sa_data_t *a = (const iptfs_sa_data_t *)_a;
    const iptfs_sa_data_t *b = (const iptfs_sa_data_t *)_b;
    if (a->key.spi != b->key.spi)
        return 0;
    if (cmp_address(&a->key.src, &b->key.src))
        return 0;
    return cmp_address(&a->key.dst, &b->key.dst) == 0;
}

#if 0
static int
key_cmp_seq(void *_a, void *_b)
{
    struct key *a = (struct key *)_a, *b = (struct key *)_b;
    int cmp;
    if ((cmp = cmp_address(a->src, b->src)))
        return cmp;
    else if ((cmp = cmp_address(a->dst, b->dst)))
        return cmp;
    else if (a->spi < b->spi)
        return -1;
    else if (a->spi > b->spi)
        return 1;
    else
        return 0;
}
#endif

static gboolean
iptfs_flow_get_esp_info(tvbuff_t *tvb, packet_info *pinfo, guint32 *spi,
                        guint32 *seq)
{
    tvbuff_t *esptvb = get_esp_tvb(tvb, pinfo);
    if (!esptvb)
        return FALSE;
    *spi = tvb_get_ntohl(esptvb, 0);
    *seq = tvb_get_ntohl(esptvb, 4);
    return TRUE;
}

#if 0
void
print_pdu_tracking_data(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tcp_tree,
                        struct tcp_multisegment_pdu *msp)
{
    proto_item *item;

    col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[cont. from #%u] ",
                           msp->first_frame);
    item = proto_tree_add_uint(tcp_tree, hf_continued, tvb, 0, 0,
                               msp->first_frame);
    proto_item_set_generated(item);
}
#endif

iptfs_sa_data_t *
iptfs_flow_packet_start(tvbuff_t *tvb, packet_info *pinfo,
                        proto_tree *iptfs_tree _U_, guint32 start,
                        guint16 block_offset, void *data _U_)
{
    iptfs_frag_data_t *first_frag;
    iptfs_sa_data_t *sa_data;
    guint32 seq;

    struct key key = {.src = pinfo->src, .dst = pinfo->dst};
    if (!iptfs_flow_get_esp_info(tvb, pinfo, &key.spi, &seq))
        return NULL;

    if (!(sa_data = (iptfs_sa_data_t *)wmem_map_lookup(sa_map, &key))) {
        sa_data = wmem_new0(wmem_file_scope(), iptfs_sa_data_t);
        sa_data->first_frags = wmem_tree_new(wmem_file_scope());
        sa_data->frames =
            wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        sa_data->key = key;
        sa_data->largest_seq = seq;
        (void)wmem_map_insert(sa_map, &key, sa_data);
    }
    sa_data->seq = seq;
    if (sa_data->largest_seq < seq)
        sa_data->largest_seq = seq;
    sa_data->frag = 0;

    /*
     * we have a block offset, or all pad other functions will handle this
     */
    if (block_offset || (tvb_get_guint8(tvb, start) & 0xF0) == 0)
        return sa_data;

    /*
     * As this packet does not continue a fragment, abort any chain we were
     * supposed to complete.
     */
    if ((first_frag = (iptfs_frag_data_t *)wmem_tree_lookup32_le(
             sa_data->first_frags, seq))) {
        /* if this is a duplicate just return */
        if (first_frag->seq == seq)
            return sa_data;

        /* If this is supposed to help the fragment, the fragment is
         * dead b/c this doesn't continue a fragment (!block_offset). */
        if (!first_frag->complete && first_frag->last_append_seq + 1 == seq) {
            /* report an error? */
            first_frag->bad_chain = TRUE;
            wmem_tree_remove32(sa_data->first_frags, seq);
        }
    }
    return sa_data;
}

/*
 * dissect_full_packet
 */
static gint
iptfs_flow_dissect_tvb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       guint8 proto, gboolean add_src)
{
    gint dislen = 0;
    if (add_src)
        add_new_data_source(pinfo, tvb, "Reassembeld Data");
    TRY
    {
        dislen = dissector_try_uint_new(ip_dissector_table, proto, tvb, pinfo,
                                        tree, FALSE, NULL);
    }
    CATCH_NONFATAL_ERRORS {}
    ENDTRY;
    return dislen;
}

/*
 * This is a full packet fragment
 */
void
iptfs_flow_full_frag(iptfs_sa_data_t *sa_data _U_, tvbuff_t *tvb,
                     packet_info *pinfo, proto_tree *tree, guint8 proto,
                     guint32 start, guint32 len, void *data _U_)
{
    tvbuff_t *next_tvb = tvb_new_subset_length(tvb, start, len);
    iptfs_flow_dissect_tvb(next_tvb, pinfo, tree, proto, FALSE);
}

iptfs_frag_data_t *
get_or_create_frag(iptfs_sa_data_t *sa_data, packet_info *pinfo, guint32 seq,
                   gboolean *is_new)
{
    if (sa_data->frag) {
        DISSECTOR_ASSERT_CMPUINT(seq, ==, sa_data->frag->seq);
        if (is_new)
            *is_new = FALSE;
        return sa_data->frag;
    }

    sa_data->frag = (iptfs_frag_data_t *)wmem_map_lookup(
        sa_data->frames, GUINT_TO_POINTER((guint)seq));
    if (sa_data->frag) {
        if (is_new)
            *is_new = FALSE;
        return sa_data->frag;
    }

    sa_data->frag = wmem_new0(wmem_file_scope(), iptfs_frag_data_t);
    sa_data->frag->frame_num = pinfo->num;
    sa_data->frag->seq = seq;
    wmem_map_insert(sa_data->frames, GUINT_TO_POINTER((guint)seq),
                    sa_data->frag);
    if (is_new)
        *is_new = TRUE;
    return sa_data->frag;
}

#define MAX_SEQ_WINDOW 32

/*
 * Walk forward from sequence to see if we complete the packet
 */
void
iptfs_flow_walk_fwd_complete(iptfs_sa_data_t *sa_data,
                             iptfs_frag_data_t *first_frag)
{
    /*
     * Try and fill out the chain.
     */
    if (first_frag->complete)
        return;

    guint32 seq;
    for (seq = first_frag->last_append_seq + 1;; seq++) {
        iptfs_frag_data_t *nfrag = (iptfs_frag_data_t *)wmem_map_lookup(
            sa_data->frames, GUINT_TO_POINTER((guint)seq));
        if (!nfrag)
            return;

        if (nfrag->all_pad) {
            first_frag->last_append_seq = seq;
            continue;
        }

        if (nfrag->end_frag_tvb) {
            first_frag->last_append_seq = seq;
            tvb_composite_append(first_frag->tvb_comp, nfrag->end_frag_tvb);
            tvb_composite_finalize(first_frag->tvb_comp);
            first_frag->complete = TRUE;
            return;
        }

        if (!nfrag->all_frag) {
            /* got a starts frag w/o an ends frag (i.e., not an all
             * frag) */
            first_frag->bad_chain = TRUE;
            wmem_tree_remove32(sa_data->first_frags, first_frag->seq);
            return;
        }

        first_frag->last_append_seq = seq;
        tvb_composite_append(first_frag->tvb_comp, nfrag->start_frag_tvb);
    }
}

static void
free_real_data(void *mem)
{
    wmem_free(wmem_file_scope(), mem);
}

/*
 * This is a continuation fragment that started an IPTFS tunnel packet
 */
void
iptfs_flow_continue_frag(iptfs_sa_data_t *sa_data, tvbuff_t *tvb,
                         packet_info *pinfo, proto_tree *tree, guint32 db_start,
                         guint32 left, guint16 block_offset,
                         void *user_data _U_)
{
    guint32 seq = sa_data->seq;
    iptfs_frag_data_t *first_frag, *frag;
    gboolean is_new;

    frag = get_or_create_frag(sa_data, pinfo, seq, &is_new);
    /* XXX we may be a first frag *and* a final frag look before us */
    /* XXX we may want to do something with the seq wrapping but it might
     * just be right to let it happen */
    first_frag = (iptfs_frag_data_t *)wmem_tree_lookup32_le(
        sa_data->first_frags, seq - 1);
    /* Handle duplicat receive */
    if (!is_new) {
        /* This can be as simple as user hovering over the packet */
        if (!first_frag || frag->all_frag)
            return;
    } else {
        frag->all_pad = (block_offset == 0);
        frag->all_frag = (block_offset && block_offset >= left);

        /* Save our fragment data */
        guint32 data_len = MIN(block_offset, left);
        const guint8 *data = (const guint8 *)tvb_memdup(wmem_file_scope(), tvb,
                                                        db_start, data_len);
        tvbuff_t *frag_tvb = tvb_new_real_data(data, data_len, data_len);
        tvb_set_free_cb(frag_tvb, free_real_data);

        if (frag->all_frag)
            frag->start_frag_tvb = frag_tvb;
        else
            frag->end_frag_tvb = frag_tvb;

        if (!first_frag)
            return;

        if (first_frag->seq == seq) {
            /* totally bogus different data for same seq */
            /* XXX We should mark this or the previous packet
             * somehow */
            fprintf(stderr,
                    "Got DUP esp seq %u with different content "
                    "other frame %d this "
                    "%d\n",
                    seq, first_frag->frame_num, frag->frame_num);
            first_frag->bad_chain = TRUE;
            wmem_tree_remove32(sa_data->first_frags, seq);
            return;
        }

        /* we shouldn't be new and yet present in the first frag */
        DISSECTOR_ASSERT(seq > first_frag->last_append_seq);
    }

    iptfs_flow_walk_fwd_complete(sa_data, first_frag);

    /* If we have a complete chain from the first frags dissect it */
    if (first_frag->complete)
        iptfs_flow_dissect_tvb(first_frag->tvb_comp, pinfo, tree,
                               first_frag->proto, TRUE);
}

void
iptfs_flow_all_pad_frag(iptfs_sa_data_t *sa_data, tvbuff_t *tvb,
                        packet_info *pinfo, proto_tree *tree, void *data)
{
    iptfs_flow_continue_frag(sa_data, tvb, pinfo, tree, 0, 0, 0, data);
}

/*
 * This is an initial fragment that ended an IPTFS tunnel packet
 */
void
iptfs_flow_initial_frag(iptfs_sa_data_t *sa_data, tvbuff_t *tvb _U_,
                        packet_info *pinfo, guint8 proto, guint32 db_start,
                        void *user_data _U_)
{
    guint32 seq = sa_data->seq;
    iptfs_frag_data_t *frag, *lookup;
    gboolean is_new;

    frag = get_or_create_frag(sa_data, pinfo, seq, &is_new);
    lookup = (iptfs_frag_data_t *)wmem_tree_lookup32(sa_data->first_frags, seq);
    if (lookup) {
        DISSECTOR_ASSERT(!is_new);
        DISSECTOR_ASSERT(frag == lookup);
        iptfs_flow_walk_fwd_complete(sa_data, frag);
        return;
#if 0
        /* XXX should we just free everything and redo? */
        fprintf(stderr, "Redoing first frag from frame %d using frame %d\n",
                lookup->frame_num, frag->frame_num);
        DISSECTOR_ASSERT(!lookup->all_frag);
        DISSECTOR_ASSERT(!lookup->all_pad);
        DISSECTOR_ASSERT(!lookup->bad_chain);
        if (frag->start_frag_tvb) {
            tvb_free_chain(frag->start_frag_tvb);
            frag->start_frag_tvb = NULL;
        }
        /* If complete then the composite was finalized and freed above */
        if (!frag->complete && frag->tvb_comp)
            tvb_free_chain(frag->start_frag_tvb);
        frag->tvb_comp = NULL;
#endif
    }

    frag->proto = proto;
    frag->complete = FALSE;

    /*
     * Each fragment gets a real tvb with the fragment data
     */
    guint left = tvb_captured_length_remaining(tvb, db_start);
    const guint8 *data =
        (const guint8 *)tvb_memdup(wmem_file_scope(), tvb, db_start, left);
    frag->start_frag_tvb = tvb_new_real_data(data, left, left);
    tvb_set_free_cb(frag->start_frag_tvb, free_real_data);

    /*
     * Create a composite tvb for the entire packet
     */
    frag->tvb_comp = tvb_new_composite();
    tvb_composite_append(frag->tvb_comp, frag->start_frag_tvb);
    frag->last_append_seq = seq;

    if (!lookup)
        wmem_tree_insert32(sa_data->first_frags, seq, frag);

    /*
     * Search forward now for existing finishers!
     */
    iptfs_flow_walk_fwd_complete(sa_data, frag);
}

static void
iptfs_flow_cleanup(void)
{
}

void
iptfs_flow_reg_handoff(void)
{
    if (!ip_dissector_table) {
        ip_dissector_table = find_dissector_table("ip.proto");

        sa_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                        key_hash, key_eq);
        register_cleanup_routine(iptfs_flow_cleanup);
    }
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 *
 * coding-style-patch-verification: CLANG
 */
