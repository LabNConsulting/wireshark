/* packet-iptfs.c
 * Routines for iptfs dissection
 * Copyright (c) 2020, LabN Consulting, L.L.C
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Created January 18 2020, Christian Hopps <chopps@gmail.com>
 */

/*
 * This code dissects the IPTFS payload type of IPsec/ESP.
 *
 * https://datatracker.ietf.org/doc/draft-ietf-ipsecme-iptfs/
 */

#include <config.h>
#include <epan/packet.h> /* Should be first Wireshark include (other than config.h) */

#include <epan/ipproto.h>

void proto_reg_handoff_iptfs(void);
void proto_register_iptfs(void);

/* implemented in packet-iptfs-flow.c */
typedef struct iptfs_sa_data iptfs_sa_data_t;

void iptfs_flow_all_pad_frag(iptfs_sa_data_t *sa_data, tvbuff_t *tvb,
                             packet_info *pinfo, proto_tree *tree, void *data);
void iptfs_flow_continue_frag(iptfs_sa_data_t *sa_data, tvbuff_t *tvb,
                              packet_info *pinfo, proto_tree *tree,
                              guint32 db_start, guint32 left,
                              guint16 block_offset, void *data);
void iptfs_flow_full_frag(iptfs_sa_data_t *sa_data, tvbuff_t *tvb,
                          packet_info *pinfo, proto_tree *tree, guint8 proto,
                          guint32 start, guint32 len, void *data);
void iptfs_flow_initial_frag(iptfs_sa_data_t *sa_data, tvbuff_t *tvb,
                             packet_info *pinfo, guint8 proto, guint32 db_start,
                             void *data);
iptfs_sa_data_t *iptfs_flow_packet_start(tvbuff_t *tvb, packet_info *pinfo,
                                         proto_tree *iptfs_tree, guint32 start,
                                         guint16 block_offset, void *data);
void iptfs_flow_reg_handoff(void);

static int proto_iptfs = -1;
static int hf_flags = -1;
static int hf_flags_v = -1;
static int hf_flags_cc = -1;
static int hf_block_offset = -1;
static int hf_rtt = -1;
static int hf_delay = -1;
static int hf_loss_rate = -1;
static int hf_last_seq = -1;
static int hf_data_block = -1;
static int hf_pad_block = -1;
static int hf_packets = -1;

int hf_iptfs_cont_from = -1;
// static expert_field ei_PROTOABBREV_EXPERTABBREV = EI_INIT;

/* Initialize the subtree pointers */
static gint ett_iptfs = -1;
static gint ett_iptfs_flags = -1;
static gint ett_iptfs_packets = -1;

static gint g_do_packet_dissection = 0;

#define IPTFS_FLAG_VERSION (0x8000)
#define IPTFS_FLAG_CC (0x4000)

/*
 * We have 6 types of data blocks:
 *
 * - db_cont :: continuation fragment, first in payload with a non-zero block
 *              offset, continues a previous IPv4 or IPv6 packet.
 * - db_frag_ipv4 :: final datablock, partial ipv4 packet
 * - db_frag_ipv6 :: final datablock, partial ipv6 packet
 * - db_ipv4 :: a full ipv4 packet
 * - db_ipv6 :: a full ipv6 packet
 * - db_pad  :: final datablock, pad fragment
 */

static void
dissect_iptfs_blocks(tvbuff_t *tvb, packet_info *pinfo, proto_tree *iptfs_tree,
                     iptfs_sa_data_t *sa_data, guint16 start,
                     guint16 block_offset, void *data)
{
    guint left, db_start = start;
    guint8 o;

    if (block_offset) {
        left = (guint)tvb_captured_length_remaining(tvb, db_start);
        guint32 adv = block_offset < left ? block_offset : left;
        if (!sa_data)
            proto_tree_add_item(iptfs_tree, hf_data_block, tvb, db_start, adv,
                                ENC_NA);
        else
            iptfs_flow_continue_frag(sa_data, tvb, pinfo, iptfs_tree, db_start,
                                     left, block_offset, data);
        db_start += block_offset;
    }

    while ((left = (guint)tvb_captured_length_remaining(tvb, db_start)) > 0) {
        guint16 lenoff, length;
        guint8 proto;

        switch ((o = tvb_get_guint8(tvb, db_start)) & 0xF0) {
        case 0x40:
            proto = IP_PROTO_IPV4;
            lenoff = 2;
            break;
        case 0x60:
            proto = IP_PROTO_IPV6;
            lenoff = 4;
            break;
        case 0x0:
            if (!sa_data)
                proto_tree_add_item(iptfs_tree, hf_pad_block, tvb, db_start, -1,
                                    ENC_NA);
            else if (db_start == start)
                iptfs_flow_all_pad_frag(sa_data, tvb, pinfo, iptfs_tree, data);
            return;
        default:
            if (!sa_data)
                proto_tree_add_item(iptfs_tree, hf_data_block, tvb, db_start,
                                    -1, ENC_NA);
            return;
        }
        length = 0;
        if ((lenoff + 2u > left) ||
            (length = tvb_get_ntohs(tvb, db_start + lenoff)) > left) {
            if (!sa_data)
                proto_tree_add_item(iptfs_tree, hf_data_block, tvb, db_start,
                                    left, ENC_NA);
            else
                iptfs_flow_initial_frag(sa_data, tvb, pinfo, proto, db_start,
                                        data);
            return;
        }

        if (!sa_data)
            proto_tree_add_item(iptfs_tree, hf_data_block, tvb, db_start,
                                length, ENC_NA);
        else
            iptfs_flow_full_frag(sa_data, tvb, pinfo, iptfs_tree, proto,
                                 db_start, length, data);
        db_start += length;
    }
}

static int
dissect_iptfs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    iptfs_sa_data_t *sa_data = NULL;
    proto_item *ti;
    proto_tree *iptfs_tree;
    guint32 block_offset;
    guint16 hdr_flags;
    gboolean is_cc;
    guint start;

    /*
     * HEURISTICS
     */

    if (tvb_captured_length(tvb) < 4)
        return 0;

    hdr_flags = tvb_get_ntohs(tvb, 0);

    /* We only dissect version 0 */
    if ((hdr_flags & IPTFS_FLAG_VERSION) != 0)
        return 0;

    /* If congestion control flags present check for header octets available
     */
    is_cc = (hdr_flags & IPTFS_FLAG_CC) != 0;
    if (is_cc && tvb_captured_length(tvb) < 16)
        return 0;
    /*** COLUMN DATA ***/

    /* There are two normal columns to fill in: the 'Protocol' column which
     * is narrow and generally just contains the constant string
     * 'PROTOABBREV', and the 'Info' column which can be much wider and
     * contain misc. summary information (for example, the port number for
     * TCP packets).
     *
     * If you are setting the column to a constant string, use
     * "col_set_str()", as it's more efficient than the other
     * "col_set_XXX()" calls.
     *
     * If
     * - you may be appending to the column later OR
     * - you have constructed the string locally OR
     * - the string was returned from a call to val_to_str()
     * then use "col_add_str()" instead, as that takes a copy of the string.
     *
     * The function "col_add_fstr()" can be used instead of "col_add_str()";
     * it takes "printf()"-like arguments. Don't use "col_add_fstr()" with a
     * format string of "%s" - just use "col_add_str()" or "col_set_str()",
     * as it's more efficient than "col_add_fstr()".
     *
     * For full details see section 1.4 of README.dissector.
     */

    /* Set the Protocol column to the constant string of PROTOABBREV */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "iptfs");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_str(pinfo->cinfo, COL_INFO, "IPTFS Payload");
    if (is_cc)
        col_append_str(pinfo->cinfo, COL_INFO, "+CC");

    /*** PROTOCOL TREE ***/

    /* Now we will create a sub-tree for our protocol and start adding
     * fields to display under that sub-tree. Most of the time the only
     * functions you will need are proto_tree_add_item() and
     * proto_item_add_subtree().
     *
     * NOTE: The offset and length values in the call to
     * proto_tree_add_item() define what data bytes to highlight in the hex
     * display window when the line in the protocol tree display
     * corresponding to that item is selected.
     *
     * Supplying a length of -1 tells Wireshark to highlight all data from
     * the offset to the end of the packet.
     */

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_iptfs, tvb, 0, -1, ENC_NA);
    iptfs_tree = proto_item_add_subtree(ti, ett_iptfs);

    // proto_tree_add_item(iptfs_tree, hf_flags, tvb, 0, 2, ENC_BIG_ENDIAN);
    static const int *msg_flags[] = {&hf_flags_v, &hf_flags_cc, NULL};
    proto_tree_add_bitmask_with_flags(iptfs_tree, tvb, 0, hf_flags,
                                      ett_iptfs_flags, msg_flags, ENC_NA,
                                      0 /* BMT_NO_FALSE */);

    proto_tree_add_item_ret_uint(iptfs_tree, hf_block_offset, tvb, 2, 2,
                                 ENC_BIG_ENDIAN, &block_offset);

    if (!is_cc)
        start = 4;
    else {
        proto_tree_add_item(iptfs_tree, hf_rtt, tvb, 4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(iptfs_tree, hf_delay, tvb, 6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(iptfs_tree, hf_loss_rate, tvb, 8, 4,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(iptfs_tree, hf_last_seq, tvb, 12, 4,
                            ENC_BIG_ENDIAN);
        start = 16;
    }

    if (tvb_captured_length_remaining(tvb, start) == 0)
        return tvb_captured_length(tvb);

    /*
     * Dissect the datablocks into tree summary then do decap.
     */
    dissect_iptfs_blocks(tvb, pinfo, iptfs_tree, sa_data, start, block_offset,
                         data);

    /* Use another sub-tree for the packets */
    ti = proto_tree_add_item(iptfs_tree, hf_packets, tvb, 0, -1, ENC_NA);
    iptfs_tree = proto_item_add_subtree(ti, ett_iptfs_packets);

    if (g_do_packet_dissection) {
        /* Stop inner packets from rewriting our column info */
        gboolean cwritable = col_get_writable(pinfo->cinfo, -1);
        col_set_writable(pinfo->cinfo, -1, FALSE);

        address src = pinfo->src;
        address dst = pinfo->dst;
        address net_src = pinfo->net_src;
        address net_dst = pinfo->net_dst;
        gboolean in_error_pkt = pinfo->flags.in_error_pkt;
        port_type ptype = pinfo->ptype;
        guint32 srcport = pinfo->srcport;
        guint32 destport = pinfo->destport;

        /* XXX Not sure about this, but we certainly can desegment */
        pinfo->can_desegment = 2;

        if ((sa_data = iptfs_flow_packet_start(tvb, pinfo, iptfs_tree, start,
                                               block_offset, data)))
            dissect_iptfs_blocks(tvb, pinfo, iptfs_tree, sa_data, start,
                                 block_offset, data);

        pinfo->src = src;
        pinfo->dst = dst;
        pinfo->net_src = net_src;
        pinfo->net_dst = net_dst;
        pinfo->flags.in_error_pkt = in_error_pkt;
        pinfo->ptype = ptype;
        pinfo->srcport = srcport;
        pinfo->destport = destport;

        col_set_writable(pinfo->cinfo, -1, cwritable);
        col_fill_in(pinfo, TRUE, TRUE);
    }
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_iptfs(void)
{
    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        {&hf_flags,
         {"Flags", "iptfs.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_flags_v,
         {"V", "iptfs.flags.v", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x8000,
          "Clear for first version of IPTFS protocol", HFILL}},
        {&hf_flags_cc,
         {"CC", "iptfs.flags.cc", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x4000,
          "Set if extended congestion control head is present", HFILL}},
        {&hf_block_offset,
         {"Block Offset", "iptfs.block_offset", FT_UINT16, BASE_HEX, NULL, 0,
          "Offset to start of next block", HFILL}},
        {&hf_rtt,
         {"RTT", "iptfs.rtt", FT_UINT16, BASE_DEC, NULL, 0,
          "Congestion Control: round trip time estimate", HFILL}},
        {&hf_delay,
         {"Delay", "iptfs.rtt", FT_UINT16, BASE_DEC, NULL, 0,
          "Congestion Control: delay in sending this info estimate", HFILL}},
        {&hf_loss_rate,
         {"Loss Rate", "iptfs.rtt", FT_UINT32, BASE_DEC, NULL, 0,
          "Congestion Control: loss rate calculation", HFILL}},
        {&hf_last_seq,
         {"Last Sequence", "iptfs.last_seq", FT_UINT32, BASE_DEC, NULL, 0,
          "Congestion Control: last sequence received by sender", HFILL}},
        {&hf_data_block,
         {"Data Block", "iptfs.data_block", FT_BYTES, SEP_SPACE, NULL, 0, NULL,
          HFILL}},
        {&hf_pad_block,
         {"Pad Block", "iptfs.pad_block", FT_BYTES, SEP_SPACE, NULL, 0, NULL,
          HFILL}},
        {&hf_iptfs_cont_from,
         {"This is a continuation to the PDU in frame", "iptfs.cont_from",
          FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          "This is a continuation to the PDU in frame #", HFILL}},
        {&hf_packets,
         {"Contained Packets", "iptfs.packets", FT_NONE, BASE_NONE, NULL, 0x0,
          "Packets completed by this payload", HFILL}},

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_iptfs,
        &ett_iptfs_flags,
        &ett_iptfs_packets,
    };

    /* Register the protocol name and description */
    proto_iptfs =
        proto_register_protocol("IP Traffic Flow Security", "IPTFS", "iptfs");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_iptfs, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /*
     * Preferences
     */
    module_t *iptfs_module = prefs_register_protocol(proto_iptfs, NULL);
    prefs_register_bool_preference(
        iptfs_module, "do_packet_dissection", "Dissect inner packets",
        "Attempt to dissect packets within IPTFS tunnel",
        &g_do_packet_dissection);

    register_dissector("iptfs", dissect_iptfs, proto_iptfs);
}

void
proto_reg_handoff_iptfs(void)
{
#define IP_PROTO_IPTFS 144
    dissector_add_uint("ip.proto", IP_PROTO_IPTFS, find_dissector("iptfs"));
    dissector_add_uint("ip.proto", 143, find_dissector("iptfs"));
    iptfs_flow_reg_handoff();
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
