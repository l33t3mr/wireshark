/* packet-rdpudp.c
 * Routines for RDP multi transport packet dissection
 * Copyright 2021, David Fort
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/conversation.h>

#include "packet-rdp.h"
#include "packet-rdpudp.h"

#define PNAME  "Remote Desktop Protocol Multi-transport"
#define PSNAME "RDPMT"
#define PFNAME "rdpmt"

void proto_register_rdpmt(void);
void proto_reg_handoff_rdpmt(void);

static dissector_handle_t rdpmt_handle;

static int proto_rdpmt = -1;

static int pf_mt_action = -1;
static int pf_mt_flags = -1;
static int pf_mt_payload_len = -1;
static int pf_mt_header_len = -1;
static int pf_mt_subheader_len = -1;
static int pf_mt_subheader_type = -1;
static int pf_mt_createreq_reqId = -1;
static int pf_mt_createreq_reserved = -1;
static int pf_mt_createreq_cookie = -1;
static int pf_mt_createresp_hrResponse = -1;

static int ett_rdpmt = -1;
static int ett_rdpudp_subheaders = -1;
static int ett_rdpmt_create_req = -1;
static int ett_rdpmt_create_resp = -1;
static int ett_rdpmt_data = -1;

static dissector_handle_t drdynvcDissector;

static const value_string rdpmt_action_vals[] = {
	{ 0x00, "CreateRequest"},
	{ 0x01, "CreateResponse"},
	{ 0x02, "Data"},
	{ 0x00, NULL}
};

static const value_string rdpmt_subheader_type_vals[] = {
	{ 0x0, "auto detect request" },
	{ 0x1, "auto detect response" },
	{ 0x0, NULL}
};


enum {
	RDPMT_TUNNEL_CREATE_REQ = 0,
	RDPMT_TUNNEL_CREATE_RESP = 1,
	RDPMT_TUNNEL_DATA = 2,
};
static int
dissect_rdpmt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	proto_item *item;
	proto_tree *tree, *subtree;
	guint8 action, subheader_len;
	guint16 payload_len;
	int offset = 0;

	item = proto_tree_add_item(parent_tree, proto_rdpmt, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_rdpmt);

	action = tvb_get_guint8(tvb, offset) & 0x0f;
	proto_tree_add_item(tree, pf_mt_action, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, pf_mt_flags, tvb, offset, 1, ENC_NA);
	offset++;

	payload_len	= tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, pf_mt_payload_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	subheader_len = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, pf_mt_header_len, tvb, offset, 1, ENC_NA);
	offset += 1;

	if (subheader_len > 4) {
		tvbuff_t *subheaders = tvb_new_subset_length(tvb,  offset, subheader_len-4);
		proto_tree *subheaders_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rdpudp_subheaders, NULL, "SubHeaders");
		dissect_rdp_bandwidth_req(subheaders, 0, pinfo, subheaders_tree, !!rdp_isServerAddressTarget(pinfo));
	}


	offset += subheader_len - 4;

	switch (action) {
	case RDPMT_TUNNEL_CREATE_REQ:
		subtree = proto_tree_add_subtree(tree, tvb, offset, payload_len, ett_rdpmt_create_req, NULL, "TunnelCreateRequest");
		proto_tree_add_item(subtree, pf_mt_createreq_reqId, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(subtree, pf_mt_createreq_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(subtree, pf_mt_createreq_cookie, tvb, offset, 16, ENC_NA);
		offset += 4;
		break;
	case RDPMT_TUNNEL_CREATE_RESP:
		subtree = proto_tree_add_subtree(tree, tvb, offset, payload_len, ett_rdpmt_create_resp, NULL, "TunnelCreateResponse");
		proto_tree_add_item(subtree, pf_mt_createresp_hrResponse, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		break;

	case RDPMT_TUNNEL_DATA:
		if (payload_len) {
			tvbuff_t *payload = tvb_new_subset_length(tvb, offset, payload_len);
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rdpmt_data, NULL, "Data");
			call_dissector(drdynvcDissector, payload, pinfo, subtree);
		}
		break;
	}

	return offset;
}

void
proto_register_rdpmt(void) {
	/* List of fields */
	static hf_register_info hf[] = {

	  { &pf_mt_action,
		{"Action", "rdpmt.action", FT_UINT8, BASE_HEX, VALS(rdpmt_action_vals), 0x0F, NULL, HFILL}
	  },
	  {&pf_mt_flags,
		{"Flags", "rdpmt.flags", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
	  },
	  {&pf_mt_payload_len,
		{"Payload length", "rdpmt.payloadlen", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  {&pf_mt_header_len,
		{"Header length", "rdpmt.headerlen", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  {&pf_mt_subheader_len,
		{"Sub header length", "rdpmt.subheaderlen", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  {&pf_mt_subheader_type,
		{"Sub header type", "rdpmt.subheadertype", FT_UINT8, BASE_HEX, VALS(rdpmt_subheader_type_vals), 0, NULL, HFILL}
	  },
	  {&pf_mt_createreq_reqId,
		{"RequestID", "rdpmt.createrequest.requestid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  {&pf_mt_createreq_reserved,
		{"Reserved", "rdpmt.createrequest.reserved", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  {&pf_mt_createreq_cookie,
		{"Security cookie", "rdpmt.createrequest.cookie", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
	  },
	  {&pf_mt_createresp_hrResponse,
		{"hrResponse", "rdpmt.createresponse.hrresponse", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL}
	  }
	};

	/* List of subtrees */
	static gint *ett[] = {
		&ett_rdpmt,
		&ett_rdpudp_subheaders,
		&ett_rdpmt_create_req,
		&ett_rdpmt_create_resp,
		&ett_rdpmt_data
	};

	/* Register protocol */
	proto_rdpmt = proto_register_protocol(PNAME, PSNAME, PFNAME);
	/* Register fields and subtrees */
	proto_register_field_array(proto_rdpmt, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	rdpmt_handle = register_dissector("rdpmt", dissect_rdpmt, proto_rdpmt);
}

static gboolean
rdpmt_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	guint8 action, header_len;
	guint16 payload_len;

	if (tvb_reported_length(tvb) <= 4)
		return FALSE;

	action = tvb_get_guint8(tvb, 0);
	if (action > 2)
		return FALSE;

	payload_len = tvb_get_guint16(tvb, 1, ENC_LITTLE_ENDIAN);
	header_len = tvb_get_guint8(tvb, 3);

	if ((header_len < 4UL) || (tvb_reported_length_remaining(tvb, header_len) < payload_len))
		return FALSE;

	if (header_len > 4) {
		guint8 subheader_len, subheader_type;

		if(header_len < 6)
			return FALSE;

		subheader_len = tvb_get_guint8(tvb, 4);
		if ((subheader_len < 2) || (subheader_len > header_len-4))
			return FALSE;

		subheader_type = tvb_get_guint8(tvb, 5);
		if (subheader_type > 1) /* AUTODETECT_REQUEST or AUTODETECT_RESPONSE */
			return FALSE;
	}

	return dissect_rdpmt(tvb, pinfo, tree, data) > 0;
}

void
proto_reg_handoff_rdpmt(void)
{
	drdynvcDissector = find_dissector("rdp_drdynvc");

	heur_dissector_add("tls", rdpmt_heur, "RDP MultiTransport", "rdpmt_tls_", proto_rdpmt, TRUE);
	heur_dissector_add("dtls", rdpmt_heur, "RDP MultiTransport", "rdpmt_dtls", proto_rdpmt, TRUE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
