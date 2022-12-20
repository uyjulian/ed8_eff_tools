# SPDX-License-Identifier: MIT

# Utility for converting .json data to .eff

# First argument is input file, second argument is output file

import sys
import array
import struct
import io
import json

convdat = {}

def get_padded_b_str(in_str, in_length, encoding="ASCII", null_terminate=True, padding=b"\x00", append_str=b""):
	b_str = (in_str.encode(encoding=encoding, errors="replace") + append_str)[:in_length]
	if len(b_str) != in_length:
		b_str += b"\x00"
	b_str += padding * (in_length - len(b_str))
	return b_str

def encode_single_and_write_to_f(dic, ind, wf):
	inf = convdat[str(ind)]
	data_key = "data_%02x" % ind
	data = dic[data_key]
	wf.write(struct.pack(inf["decodefmt"], *data))

def encode_array_and_write_to_f(dic, ind, wf):
	inf = convdat[str(ind)]
	data_key = "data_%02x" % ind
	data = dic[data_key]
	wf.write(struct.pack("I", len(data)))
	for x in data:
		wf.write(struct.pack(inf["decodefmt"], *x))

def encode_array_nested_and_write_to_f(dic, ind, wf):
	inf = convdat[str(ind)]
	data_key = "data_%02x" % ind
	data = dic[data_key]
	wf.write(struct.pack("I", len(data)))
	for x in data:
		wf.write(struct.pack("I", len(x)))
		for xx in x:
			wf.write(struct.pack(inf["decodefmt"], *xx))

try:
	in_fn = sys.argv[1]
	out_fn = sys.argv[2]
	with open(in_fn, "r") as f, open(out_fn, "wb") as wf:
		eff_root = json.load(f)
		ver = eff_root["version"]
		if (ver >= 0x6A and ver <= 0x6D) or ver == 4:
			pass
		else:
			raise Exception("Invalid version!")
		wf.write(struct.pack("I", ver))
		convdat = eff_root["schema"]
		unk1 = eff_root["unk1"]
		wf.write(struct.pack("I", unk1))
		effect_name = eff_root["effect_name"]
		if ver >= 0x6D:
			effect_name = get_padded_b_str(effect_name, 32, encoding="ms932")
			wf.write(struct.pack("I", len(effect_name)))
		else:
			padding_to_use = b"\x00"
			# Workaround for roundtripping for encoder forgetting to clear stack
			if "effect_name_padbyte" in eff_root:
				padding_to_use = eff_root["effect_name_padbyte"].to_bytes(1, byteorder="little")
			effect_name = get_padded_b_str(effect_name, 16, encoding="ms932", padding=padding_to_use)
		wf.write(effect_name)
		v26_list = eff_root["v26_list"]
		v26 = len(v26_list)
		wf.write(struct.pack("I", v26))
		for b_str in v26_list:
			wf.write(get_padded_b_str(b_str, 20, encoding="ASCII"))
		v40_list = eff_root["v40_list"]
		v40 = len(v40_list)
		wf.write(struct.pack("I", v40))
		for b_str in v40_list:
			wf.write(get_padded_b_str(b_str, 36, encoding="ASCII"))
		v310_list = eff_root["v310_list"]
		v310 = len(v310_list)
		wf.write(struct.pack("I", v310))
		for object_v310 in v310_list:
			if True:
				extra_byte_roundtrip = b""
				if "segment_name_lastbyte" in object_v310:
					extra_byte_roundtrip = object_v310["segment_name_lastbyte"].to_bytes(1, byteorder="little")
				wf.write(get_padded_b_str(object_v310["segment_name"], 16, encoding="ms932", append_str=extra_byte_roundtrip))
			wf.write(get_padded_b_str(object_v310["fn_name_1"], 16, encoding="ASCII"))
			wf.write(get_padded_b_str(object_v310["fn_name_2"], 16, encoding="ASCII"))
			structure_usage_flags = 0
			if ver >= 0x6A:
				structure_usage_flags = object_v310["data_01"][1]
				encode_single_and_write_to_f(object_v310, 0x01, wf)
			encode_single_and_write_to_f(object_v310, 0x02, wf)
			if ver >= 0x6B:
				encode_single_and_write_to_f(object_v310, 0x03, wf)
			encode_single_and_write_to_f(object_v310, 0x04, wf)
			if ver < 0x6B:
				encode_single_and_write_to_f(object_v310, 0x05, wf)
			encode_single_and_write_to_f(object_v310, 0x06, wf)
			if ver >= 0x6C:
				encode_single_and_write_to_f(object_v310, 0x07, wf)
			encode_single_and_write_to_f(object_v310, 0x08, wf)
			encode_array_and_write_to_f(object_v310, 0x09, wf)
			encode_array_and_write_to_f(object_v310, 0x0A, wf)
			encode_array_and_write_to_f(object_v310, 0x0B, wf)
			encode_array_and_write_to_f(object_v310, 0x0C, wf)
			encode_array_and_write_to_f(object_v310, 0x0D, wf)
			encode_array_and_write_to_f(object_v310, 0x0E, wf)
			if structure_usage_flags & 0x1000000 != 0:
				encode_array_and_write_to_f(object_v310, 0x0F, wf)
			if structure_usage_flags & 0x4000000 != 0:
				encode_array_and_write_to_f(object_v310, 0x10, wf)
			if structure_usage_flags & 0x8000000 != 0:
				encode_array_and_write_to_f(object_v310, 0x11, wf)
			if structure_usage_flags & 0x20000000 != 0:
				encode_array_and_write_to_f(object_v310, 0x12, wf)
			if structure_usage_flags & 0x02000000 != 0:
				encode_array_nested_and_write_to_f(object_v310, 0x13, wf)
			encode_array_and_write_to_f(object_v310, 0x14, wf)
			if ver <= 4:
				encode_single_and_write_to_f(object_v310, 0x15, wf)
				structure_usage_flags = 3
			if structure_usage_flags & 0x002 != 0:
				encode_single_and_write_to_f(object_v310, 0x16, wf)
			if structure_usage_flags & 0x001 != 0:
				if ver >= 0x6B:
					encode_array_and_write_to_f(object_v310, 0x17, wf)
				else:
					encode_single_and_write_to_f(object_v310, 0x18, wf)
			if structure_usage_flags & 0x010 != 0: # non existant!
				encode_single_and_write_to_f(object_v310, 0x19, wf)
			if structure_usage_flags & 0x004 != 0:
				encode_single_and_write_to_f(object_v310, 0x1A, wf)
			if structure_usage_flags & 0x008 != 0:
				encode_single_and_write_to_f(object_v310, 0x1B, wf)
			if ver >= 0x6A:
				encode_array_and_write_to_f(object_v310, 0x1C, wf)
			if structure_usage_flags & 0x020 != 0:
				encode_single_and_write_to_f(object_v310, 0x1D, wf)
			if structure_usage_flags & 0x040 != 0:
				encode_single_and_write_to_f(object_v310, 0x1E, wf)
			if structure_usage_flags & 0x080 != 0:
				encode_single_and_write_to_f(object_v310, 0x1F, wf)
			if structure_usage_flags & 0x100 != 0:
				encode_single_and_write_to_f(object_v310, 0x20, wf)
			if structure_usage_flags & 0x200 != 0:
				encode_single_and_write_to_f(object_v310, 0x21, wf)
		wf.write(b"\x00" * 8) # padding? why?
except Exception as e:
	print(sys.argv[1], "failed")
	raise e

