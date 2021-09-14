/* packet-ng.c
 * Routines for NGControl dissection
 * Copyright 2021, Amr Abdou abdohamr@yahoo.com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: LICENSE
 */

/*
 * (A short description of the protocol including links to specifications,
 *  detailed documentation, etc.)
 */

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>


static guint udp_port = 56424;

void proto_register_ng(void);

void proto_reg_handoff_ng(void);

static int proto_ng = -1;

static int hf_ng_bencode = -1;
static int hf_ng_cookie = -1;

/* Tree items */
static gint ett_ng = -1;
static gint ett_ng_bencode = -1;


/* Request/response tracking */
static int hf_ng_request_in = -1;
static int hf_ng_response_in = -1;

typedef struct _ng_info {
    guint32 req_frame;
    guint32 resp_frame;
} ng_info_t;

typedef struct _ng_conv_info {
    wmem_tree_t *trans;
} ng_conv_info_t;



static dissector_handle_t ng_handle;
static dissector_handle_t bencode_handle;


static ng_info_t* ng_add_tid(gboolean is_request, tvbuff_t *tvb, packet_info *pinfo, proto_tree *ng_tree, ng_conv_info_t *ng_conv, const guint8* cookie){
    ng_info_t *ng_info;
    proto_item *pi;

    if (!PINFO_FD_VISITED(pinfo)){
        if (is_request){
            ng_info = wmem_new0(wmem_file_scope(), ng_info_t);
            ng_info->req_frame = pinfo->num;
            wmem_tree_insert_string(ng_conv->trans, cookie, ng_info, 0);
        } else{
            ng_info = (ng_info_t *)wmem_tree_lookup_string(ng_conv->trans, cookie, 0);
            if(ng_info){
                ng_info->resp_frame = pinfo->num;
            }
        }

    } else {
        ng_info = (ng_info_t *)wmem_tree_lookup_string(ng_conv->trans, cookie, 0);
        if (ng_info && (is_request ? ng_info->resp_frame : ng_info->req_frame)) {
            pi = proto_tree_add_uint(ng_tree, is_request ? hf_ng_response_in : hf_ng_request_in, tvb, 0, 0, is_request ? ng_info->resp_frame : ng_info->req_frame);
            proto_item_set_generated(pi);
        }
    }
    return ng_info;

}

static int dissect_ng(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    proto_item *ti;
    proto_tree *ng_tree;
    const guint8 *cookie = NULL;

    tvbuff_t *subtvb;

    conversation_t *conversation;
    ng_conv_info_t *ng_conv;

    // find Cookie by offset
    offset = tvb_find_guint8(tvb, offset, -1, ' ');
    // if no cookie is found or buff boundary reached
    if (offset == -1)
        return 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NG");
    col_set_str(pinfo->cinfo, COL_INFO, "SipWise NG Protocol");

    col_clear(pinfo->cinfo, COL_INFO);

    // add an item NG to ws tree
    ti = proto_tree_add_item(tree, proto_ng, tvb, 0, -1, ENC_NA);

    // add a subtree to the item
    ng_tree = proto_item_add_subtree(ti, ett_ng);

    // add value of cookie to tree item
    proto_tree_add_item_ret_string(ng_tree, hf_ng_cookie, tvb, 0, offset, ENC_ASCII | ENC_NA, pinfo->pool, &cookie);

    // add bencode as an item to NG Tree
    ti = proto_tree_add_item(ng_tree, hf_ng_bencode, tvb, offset, -1, ENC_ASCII | ENC_NA);
    // add bencode sub tree to NG tree
    ng_tree = proto_item_add_subtree(ti, ett_ng_bencode);

    // detect req-resp
    /* Try to create conversation */
    conversation = find_or_create_conversation(pinfo);
    ng_conv = (ng_conv_info_t *)conversation_get_proto_data(conversation, proto_ng);
    if (!ng_conv) {
        ng_conv = wmem_new(wmem_file_scope(), ng_conv_info_t);
        ng_conv->trans = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conversation, proto_ng, ng_conv);
    }
    ng_add_tid(FALSE, tvb, pinfo, ng_tree, ng_conv, cookie);

    // dissect bencode

    /* Skip whitespace */
    offset = tvb_skip_wsp(tvb, offset + 1, -1);


    subtvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(bencode_handle, subtvb, pinfo, ng_tree);



    return tvb_captured_length(tvb);

}

void proto_register_ng(void) {
    static hf_register_info hf[] = {
            {
                    &hf_ng_cookie,
                    {
                            "Cookie",
                            "ng.cookie",
                            FT_STRING,
                            BASE_NONE,
                            NULL,
                            0x0,
                            NULL,
                            HFILL
                    }
            },
            {
                    &hf_ng_bencode,
                    {
                            "NGProtocol bencoded payload",
                            "ng.bencode",
                            FT_STRING,
                            BASE_NONE,
                            NULL,
                            0x0,
                            "Serialized structure of integers, dictionaries, strings and lists.",
                            HFILL
                    }
            }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
            &ett_ng,
            &ett_ng_bencode
    };


    proto_ng = proto_register_protocol("SipWise NG Protocol", "NG", "ng");

    proto_register_field_array(proto_ng, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    ng_handle = register_dissector("ng", dissect_ng, proto_ng);


}

void
proto_reg_handoff_ng(void) {

//    ng_handle = find_dissector_add_dependency("ng", proto_ng);
    dissector_add_uint_with_preference ("udp.port", udp_port, ng_handle);
    bencode_handle = find_dissector_add_dependency("bencode", proto_ng);

}