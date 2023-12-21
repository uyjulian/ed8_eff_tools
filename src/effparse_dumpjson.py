# SPDX-License-Identifier: MIT

# Utility for converting .eff data to .json

# First argument is input file, second argument is output file

import sys
import array
import struct
import io
import json

convdat = {
	0x01 : { # Checked
		"size" : 16,
		"decodefmt" : "IIII",
	},
	0x02 : { # Checked
		"size" : 32,
		"decodefmt" : "IIIIIIII",
	},
	0x03 : { # Checked
		"size" : 8,
		"decodefmt" : "ff",
	},
	0x04 : { # Checked
		"size" : 48,
		"decodefmt" : "ffffffffffff",
	},
	0x05 : { # Checked, its just all 0s
		"size" : 12,
		"decodefmt" : "fff",
	},
	0x06 : { # Checked
		"size" : 36,
		"decodefmt" : "fffffffff",
	},
	0x07 : { # Checked
		"size" : 16,
		"decodefmt" : "ffff",
	},
	0x08 : { # Checked
		"size" : 32,
		"decodefmt" : "ffffffff",
	},
	0x09 : { # Checked
		"size" : 48,
		"decodefmt" : "fffffffffIIf",
	},
	0x0A : {
		"size" : 48,
		"decodefmt" : "fffffffffIIf",
	},
	0x0B : {
		"size" : 48,
		"decodefmt" : "fffffffffIIf",
	},
	0x0C : {
		"size" : 48,
		"decodefmt" : "fffffffffIIf",
	},
	0x0D : {
		"size" : 48,
		"decodefmt" : "fffffffffIIf",
	},
	0x0E : {
		"size" : 48,
		"decodefmt" : "fffffffffIIf",
	},
	0x0F : {
		"size" : 48,
		"decodefmt" : "fffffffffIIf",
	},
	0x10 : {
		"size" : 48,
		"decodefmt" : "fffffffffIIf",
	},
	0x11 : {
		"size" : 48,
		"decodefmt" : "fffffffffIIf",
	},
	0x12 : {
		"size" : 48,
		"decodefmt" : "fffffffffIIf",
	},
	0x13 : {
		"size" : 48,
		"decodefmt" : "fffffffffIIf",
	},
	0x14 : {
		"size" : 48,
		"decodefmt" : "IIIfIIIIffff",
	},
	0x15 : {
		"size" : 8, # Checked, all 0s
		"decodefmt" : "ff",
	},
	0x16 : {
		"size" : 64, # Checked, all 0s
		"decodefmt" : "ffffffffffffffff",
	},
	0x17 : {
		"size" : 72, # Partially checked
		"decodefmt" : "IIIfIfffffffffffII",
	},
	0x18 : {
		"size" : 16, # Checked
		"decodefmt" : "Ifff",
	},
	0x19 : {
		"size" : 16, # Non existant
		"decodefmt" : "Ifff",
	},
	0x1A : {
		"size" : 32, # Checked
		"decodefmt" : "IffIffff",
	},
	0x1B : {
		"size" : 96, # Checked
		"decodefmt" : "ffffffffffffffffffffffff",
	},
	0x1C : {
		"size" : 12, # Checked, last 2 elms are always 0
		"decodefmt" : "Iff",
	},
	0x1D : {
		"size" : 24, # Checked
		"decodefmt" : "IIIIff",
	},
	0x1E : {
		"size" : 16, # Checked
		"decodefmt" : "ffff",
	},
	0x1F : {
		"size" : 32, # Checked
		"decodefmt" : "ffffffff",
	},
	0x20 : {
		"size" : 8, # Checked
		"decodefmt" : "If",
	},
	0x21 : {
		"size" : 52,
		"decodefmt" : "IIIffffffffff",
	},
}

def decode_single_and_write_to_dic(dic, ind, f):
	inf = convdat[ind]
	tmp = f.read(inf["size"])
	if dic != None:
		dic["data_%02x" % ind] = list(struct.unpack(inf["decodefmt"], tmp))
	return tmp

def decode_array_and_write_to_dic(dic, ind, f, cnt):
	inf = convdat[ind]
	arr = []
	for i in range(cnt):
		tmp = f.read(inf["size"])
		arr.append(list(struct.unpack(inf["decodefmt"], tmp)))
	if dic != None:
		dic["data_%02x" % ind] = arr
	return arr

def trim_bytes_to_nullterm(instr):
	return instr[:instr.index(b"\x00")]

try:
	in_fn = sys.argv[1]
	out_fn = sys.argv[2]
	with open(in_fn, "rb") as f:
		eff_root = {}
		ver, = struct.unpack("I", f.read(4))
		if (ver >= 0x6A and ver <= 0x6D) or ver == 4:
			pass
		else:
			raise Exception("Invalid version!")
		eff_root["schema"] = convdat
		eff_root["version"] = ver
		unk1, = struct.unpack("I", f.read(4)) # not used?
		eff_root["unk1"] = unk1
		effect_name_length = 16
		if ver >= 0x6D:
			effect_name_length, = struct.unpack("I", f.read(4))
		effect_name_untrimmed = f.read(effect_name_length)
		if ver < 0x6D:
			if effect_name_untrimmed[-1:] == b"\xFE":
				eff_root["effect_name_padbyte"] = effect_name_untrimmed[-1:][0]
		effect_name = trim_bytes_to_nullterm(effect_name_untrimmed).decode(encoding="ms932")
		eff_root["effect_name"] = effect_name
		v26, = struct.unpack("I", f.read(4))
		v26_list = []
		for i in range(v26):
			v26_list.append(trim_bytes_to_nullterm(f.read(20)).decode("ASCII"))
		eff_root["v26_list"] = v26_list
		v40, = struct.unpack("I", f.read(4))
		v40_list = []
		for i in range(v40):
			v40_list.append(trim_bytes_to_nullterm(f.read(36)).decode("ASCII"))
		eff_root["v40_list"] = v40_list
		v310, = struct.unpack("I", f.read(4))
		v310_list = []
		for i in range(v310):
			object_v310 = {}
			# NOTE: some names are truncated.
			# If you try to decode they you will get decode error due to incomplete multibyte sequence
			segment_name_undecoded = trim_bytes_to_nullterm(f.read(16))
			segment_name = segment_name_undecoded.decode(encoding="ms932", errors="replace")
			if len(segment_name_undecoded) == 15:
				if segment_name[-1:] == "�":
					segment_name = segment_name[:-1]
					object_v310["segment_name_lastbyte"] = segment_name_undecoded[-1:][0]
			object_v310["segment_name"] = segment_name
			fn_name_1 = trim_bytes_to_nullterm(f.read(16)).decode("ASCII")
			object_v310["fn_name_1"] = fn_name_1
			fn_name_2 = trim_bytes_to_nullterm(f.read(16)).decode("ASCII")
			object_v310["fn_name_2"] = fn_name_2
			structure_usage_flags = 0
			if ver >= 0x6A:
				tmp = decode_single_and_write_to_dic(object_v310, 0x01, f)
				_, structure_usage_flags, _, _ = struct.unpack("IIII", tmp)
			decode_single_and_write_to_dic(object_v310, 0x02, f)
			if ver >= 0x6B:
				# The following seems to always be 0?
				decode_single_and_write_to_dic(object_v310, 0x03, f)
			decode_single_and_write_to_dic(object_v310, 0x04, f)
			if ver < 0x6B:
				decode_single_and_write_to_dic(object_v310, 0x05, f)
			decode_single_and_write_to_dic(object_v310, 0x06, f)
			if ver >= 0x6C:
				decode_single_and_write_to_dic(object_v310, 0x07, f)
			decode_single_and_write_to_dic(object_v310, 0x08, f)
			v61, = struct.unpack("I", f.read(4))
			decode_array_and_write_to_dic(object_v310, 0x09, f, v61)
			v76, = struct.unpack("I", f.read(4))
			decode_array_and_write_to_dic(object_v310, 0x0A, f, v76)
			v91, = struct.unpack("I", f.read(4))
			decode_array_and_write_to_dic(object_v310, 0x0B, f, v91)
			v106, = struct.unpack("I", f.read(4))
			decode_array_and_write_to_dic(object_v310, 0x0C, f, v106)
			v121, = struct.unpack("I", f.read(4))
			decode_array_and_write_to_dic(object_v310, 0x0D, f, v121)
			v136, = struct.unpack("I", f.read(4))
			decode_array_and_write_to_dic(object_v310, 0x0E, f, v136)
			if structure_usage_flags & 0x1000000 != 0:
				v152, = struct.unpack("I", f.read(4))
				decode_array_and_write_to_dic(object_v310, 0x0F, f, v152)
			if structure_usage_flags & 0x4000000 != 0:
				v166, = struct.unpack("I", f.read(4))
				decode_array_and_write_to_dic(object_v310, 0x10, f, v166)
			if structure_usage_flags & 0x8000000 != 0:
				v180, = struct.unpack("I", f.read(4))
				decode_array_and_write_to_dic(object_v310, 0x11, f, v180)
			if structure_usage_flags & 0x20000000 != 0:
				v194, = struct.unpack("I", f.read(4))
				decode_array_and_write_to_dic(object_v310, 0x12, f, v194)
			if structure_usage_flags & 0x02000000 != 0:
				v208, = struct.unpack("I", f.read(4))
				tmparr1 = []
				for i in range(v208):
					v209, = struct.unpack("I", f.read(4))
					tmparr1.append(decode_array_and_write_to_dic(None, 0x13, f, v209))
				object_v310["data_%02X" % 0x13] = tmparr1
			v224, = struct.unpack("I", f.read(4))
			decode_array_and_write_to_dic(object_v310, 0x14, f, v224)
			if ver <= 4:
				decode_single_and_write_to_dic(object_v310, 0x15, f)
				structure_usage_flags = 3
			if structure_usage_flags & 0x002 != 0:
				decode_single_and_write_to_dic(object_v310, 0x16, f)
			if structure_usage_flags & 0x001 != 0:
				if ver >= 0x6B:
					v256, = struct.unpack("I", f.read(4))
					decode_array_and_write_to_dic(object_v310, 0x17, f, v256)
				else:
					decode_single_and_write_to_dic(object_v310, 0x18, f)
			if structure_usage_flags & 0x010 != 0: # non existant!
				decode_single_and_write_to_dic(object_v310, 0x19, f)
			if structure_usage_flags & 0x004 != 0:
				decode_single_and_write_to_dic(object_v310, 0x1A, f)
			if structure_usage_flags & 0x008 != 0:
				decode_single_and_write_to_dic(object_v310, 0x1B, f)
			if ver >= 0x6A:
				v275, = struct.unpack("I", f.read(4))
				decode_array_and_write_to_dic(object_v310, 0x1C, f, v275)
			if structure_usage_flags & 0x020 != 0:
				decode_single_and_write_to_dic(object_v310, 0x1D, f)
			if structure_usage_flags & 0x040 != 0:
				decode_single_and_write_to_dic(object_v310, 0x1E, f)
			if structure_usage_flags & 0x080 != 0:
				decode_single_and_write_to_dic(object_v310, 0x1F, f)
			if structure_usage_flags & 0x100 != 0:
				decode_single_and_write_to_dic(object_v310, 0x20, f)
			if structure_usage_flags & 0x200 != 0:
				decode_single_and_write_to_dic(object_v310, 0x21, f)
			if ver < 0x6B:
				pass # ???
			v310_list.append(object_v310)
		if ver <= 4:
			pass # ???
		eff_root["v310_list"] = v310_list
		with open(out_fn, "w", encoding="utf-8") as wf:
			json.dump(eff_root, wf, indent=True, ensure_ascii=False)
except Exception as e:
	print(sys.argv[1], "failed")
	raise e



