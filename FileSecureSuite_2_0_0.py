#!/usr/bin/env python3
"""File Secure Suite graphical application.

Provides RSA key management and AES-256-GCM/RSA-4096 encryption for text
and files. Requires PySide6, cryptography, and fss_core_1_1_0.py in the
same directory. The QR generator is embedded. Generated data is stored beside
the application.
"""

from __future__ import annotations

APP_VERSION = "2.0.0"

import os
import sys
import secrets
import hashlib
import datetime
import base64
import time
import struct
import zlib
import stat
import collections, itertools, re
from collections.abc import Sequence
from typing import Optional, Union

# 
# QR Code generator library (Python)
# 
# Copyright (c) Project Nayuki. (MIT License)
# https://www.nayuki.io/page/qr-code-generator-library
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
# - The Software is provided "as is", without warranty of any kind, express or
#   implied, including but not limited to the warranties of merchantability,
#   fitness for a particular purpose and noninfringement. In no event shall the
#   authors or copyright holders be liable for any claim, damages or other
#   liability, whether in an action of contract, tort or otherwise, arising from,
#   out of or in connection with the Software or the use or other dealings in the
#   Software.
# 


# ---- QR Code symbol class ----

class QrCode:
	"""A QR Code symbol (ISO/IEC 18004 Model 2), covering versions 1-40, all 4 error
	correction levels, and the numeric/alphanumeric/byte encoding modes. FSS only ever
	calls QrCode.encode_text() (to render the public-key export QR); encode_segments()
	and the constructor below are the encoding/drawing machinery that call needs."""
	
	# ---- Static factory function ----
	
	@staticmethod
	def encode_text(text: str, ecl: QrCode.Ecc) -> QrCode:
		"""Returns a QR Code representing the given Unicode text string at the given
		error correction level. The smallest possible QR Code version is automatically
		chosen for the output. The ECC level of the result may be higher than the ecl
		argument if it can be done without increasing the version."""
		segs: list[QrSegment] = QrSegment.make_segments(text)
		return QrCode.encode_segments(segs, ecl)
	
	
	@staticmethod
	def encode_segments(segs: Sequence[QrSegment], ecl: QrCode.Ecc, minversion: int = 1, maxversion: int = 40, mask: int = -1, boostecl: bool = True) -> QrCode:
		"""Returns a QR Code representing the given segments with the given encoding parameters.
		The smallest possible QR Code version within the given range is automatically
		chosen for the output. Iff boostecl is true, then the ECC level of the result
		may be higher than the ecl argument if it can be done without increasing the
		version. The mask number is either between 0 to 7 (inclusive) to force that
		mask, or -1 to automatically choose an appropriate mask (which may be slow)."""
		
		if not (QrCode.MIN_VERSION <= minversion <= maxversion <= QrCode.MAX_VERSION) or not (-1 <= mask <= 7):
			raise ValueError("Invalid value")
		
		# Find the minimal version number to use
		for version in range(minversion, maxversion + 1):
			datacapacitybits: int = QrCode._get_num_data_codewords(version, ecl) * 8  # Number of data bits available
			datausedbits: Optional[int] = QrSegment.get_total_bits(segs, version)
			if (datausedbits is not None) and (datausedbits <= datacapacitybits):
				break  # This version number is found to be suitable
			if version >= maxversion:  # All versions in the range could not fit the given data
				msg: str = "Segment too long"
				if datausedbits is not None:
					msg = f"Data length = {datausedbits} bits, Max capacity = {datacapacitybits} bits"
				raise DataTooLongError(msg)
		assert datausedbits is not None
		
		# Increase the error correction level while the data still fits in the current version number
		for newecl in (QrCode.Ecc.MEDIUM, QrCode.Ecc.QUARTILE, QrCode.Ecc.HIGH):  # From low to high
			if boostecl and (datausedbits <= QrCode._get_num_data_codewords(version, newecl) * 8):
				ecl = newecl
		
		# Concatenate all segments to create the data bit string
		bb = _BitBuffer()
		for seg in segs:
			bb.append_bits(seg.get_mode().get_mode_bits(), 4)
			bb.append_bits(seg.get_num_chars(), seg.get_mode().num_char_count_bits(version))
			bb.extend(seg._bitdata)
		assert len(bb) == datausedbits
		
		# Add terminator and pad up to a byte if applicable
		datacapacitybits = QrCode._get_num_data_codewords(version, ecl) * 8
		assert len(bb) <= datacapacitybits
		bb.append_bits(0, min(4, datacapacitybits - len(bb)))
		bb.append_bits(0, -len(bb) % 8)  # Note: Python's modulo on negative numbers behaves better than C family languages
		assert len(bb) % 8 == 0
		
		# Pad with alternating bytes until data capacity is reached
		for padbyte in itertools.cycle((0xEC, 0x11)):
			if len(bb) >= datacapacitybits:
				break
			bb.append_bits(padbyte, 8)
		
		# Pack bits into bytes in big endian
		datacodewords = bytearray([0] * (len(bb) // 8))
		for (i, bit) in enumerate(bb):
			datacodewords[i >> 3] |= bit << (7 - (i & 7))
		
		# Create the QR Code object
		return QrCode(version, ecl, datacodewords, mask)
	
	
	# ---- Private fields ----
	
	# The version number of this QR Code, which is between 1 and 40 (inclusive).
	# This determines the size of this barcode.
	_version: int
	
	# The width and height of this QR Code, measured in modules, between
	# 21 and 177 (inclusive). This is equal to version * 4 + 17.
	_size: int
	
	# The error correction level used in this QR Code.
	_errcorlvl: QrCode.Ecc
	
	# The index of the mask pattern used in this QR Code, which is between 0 and 7 (inclusive).
	# Even if a QR Code is created with automatic masking requested (mask = -1),
	# the resulting object still has a mask value between 0 and 7.
	_mask: int
	
	# The modules of this QR Code (False = light, True = dark).
	# Immutable after constructor finishes. Accessed through get_module().
	_modules: list[list[bool]]
	
	# Indicates function modules that are not subjected to masking. Discarded when constructor finishes.
	_isfunction: list[list[bool]]
	
	
	# ---- Constructor (low level) ----
	
	def __init__(self, version: int, errcorlvl: QrCode.Ecc, datacodewords: Union[bytes,Sequence[int]], msk: int) -> None:
		"""Creates a new QR Code with the given version number,
		error correction level, data codeword bytes, and mask number.
		This is a low-level API that most users should not use directly.
		A mid-level API is the encode_segments() function."""
		
		# Check scalar arguments and set fields
		if not (QrCode.MIN_VERSION <= version <= QrCode.MAX_VERSION):
			raise ValueError("Version value out of range")
		if not (-1 <= msk <= 7):
			raise ValueError("Mask value out of range")
		
		self._version = version
		self._size = version * 4 + 17
		self._errcorlvl = errcorlvl
		
		# Initialize both grids to be size*size arrays of Boolean false
		self._modules    = [[False] * self._size for _ in range(self._size)]  # Initially all light
		self._isfunction = [[False] * self._size for _ in range(self._size)]
		
		# Compute ECC, draw modules
		self._draw_function_patterns()
		allcodewords: bytes = self._add_ecc_and_interleave(bytearray(datacodewords))
		self._draw_codewords(allcodewords)
		
		# Do masking
		if msk == -1:  # Automatically choose best mask
			minpenalty: int = 1 << 32
			for i in range(8):
				self._apply_mask(i)
				self._draw_format_bits(i)
				penalty = self._get_penalty_score()
				if penalty < minpenalty:
					msk = i
					minpenalty = penalty
				self._apply_mask(i)  # Undoes the mask due to XOR
		assert 0 <= msk <= 7
		self._mask = msk
		self._apply_mask(msk)  # Apply the final choice of mask
		self._draw_format_bits(msk)  # Overwrite old format bits
		
		del self._isfunction
	
	
	# ---- Accessor methods ----
	
	def get_version(self) -> int:
		"""Returns this QR Code's version number, in the range [1, 40]."""
		return self._version
	
	def get_size(self) -> int:
		"""Returns this QR Code's size, in the range [21, 177]."""
		return self._size
	
	def get_error_correction_level(self) -> QrCode.Ecc:
		"""Returns this QR Code's error correction level."""
		return self._errcorlvl
	
	def get_mask(self) -> int:
		"""Returns this QR Code's mask, in the range [0, 7]."""
		return self._mask
	
	def get_module(self, x: int, y: int) -> bool:
		"""Returns the color of the module (pixel) at the given coordinates, which is False
		for light or True for dark. The top left corner has the coordinates (x=0, y=0).
		If the given coordinates are out of bounds, then False (light) is returned."""
		return (0 <= x < self._size) and (0 <= y < self._size) and self._modules[y][x]
	
	
	# ---- Private helper methods for constructor: Drawing function modules ----
	
	def _draw_function_patterns(self) -> None:
		"""Reads this object's version field, and draws and marks all function modules."""
		# Draw horizontal and vertical timing patterns
		for i in range(self._size):
			self._set_function_module(6, i, i % 2 == 0)
			self._set_function_module(i, 6, i % 2 == 0)
		
		# Draw 3 finder patterns (all corners except bottom right; overwrites some timing modules)
		self._draw_finder_pattern(3, 3)
		self._draw_finder_pattern(self._size - 4, 3)
		self._draw_finder_pattern(3, self._size - 4)
		
		# Draw numerous alignment patterns
		alignpatpos: list[int] = self._get_alignment_pattern_positions()
		numalign: int = len(alignpatpos)
		skips: Sequence[tuple[int,int]] = ((0, 0), (0, numalign - 1), (numalign - 1, 0))
		for i in range(numalign):
			for j in range(numalign):
				if (i, j) not in skips:  # Don't draw on the three finder corners
					self._draw_alignment_pattern(alignpatpos[i], alignpatpos[j])
		
		# Draw configuration data
		self._draw_format_bits(0)  # Dummy mask value; overwritten later in the constructor
		self._draw_version()
	
	
	def _draw_format_bits(self, mask: int) -> None:
		"""Draws two copies of the format bits (with its own error correction code)
		based on the given mask and this object's error correction level field."""
		# Calculate error correction code and pack bits
		data: int = self._errcorlvl.formatbits << 3 | mask  # errCorrLvl is uint2, mask is uint3
		rem: int = data
		for _ in range(10):
			rem = (rem << 1) ^ ((rem >> 9) * 0x537)
		bits: int = (data << 10 | rem) ^ 0x5412  # uint15
		assert bits >> 15 == 0
		
		# Draw first copy
		for i in range(0, 6):
			self._set_function_module(8, i, _get_bit(bits, i))
		self._set_function_module(8, 7, _get_bit(bits, 6))
		self._set_function_module(8, 8, _get_bit(bits, 7))
		self._set_function_module(7, 8, _get_bit(bits, 8))
		for i in range(9, 15):
			self._set_function_module(14 - i, 8, _get_bit(bits, i))
		
		# Draw second copy
		for i in range(0, 8):
			self._set_function_module(self._size - 1 - i, 8, _get_bit(bits, i))
		for i in range(8, 15):
			self._set_function_module(8, self._size - 15 + i, _get_bit(bits, i))
		self._set_function_module(8, self._size - 8, True)  # Always dark
	
	
	def _draw_version(self) -> None:
		"""Draws two copies of the version bits (with its own error correction code),
		based on this object's version field, iff 7 <= version <= 40."""
		if self._version < 7:
			return
		
		# Calculate error correction code and pack bits
		rem: int = self._version  # version is uint6, in the range [7, 40]
		for _ in range(12):
			rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
		bits: int = self._version << 12 | rem  # uint18
		assert bits >> 18 == 0
		
		# Draw two copies
		for i in range(18):
			bit: bool = _get_bit(bits, i)
			a: int = self._size - 11 + i % 3
			b: int = i // 3
			self._set_function_module(a, b, bit)
			self._set_function_module(b, a, bit)
	
	
	def _draw_finder_pattern(self, x: int, y: int) -> None:
		"""Draws a 9*9 finder pattern including the border separator,
		with the center module at (x, y). Modules can be out of bounds."""
		for dy in range(-4, 5):
			for dx in range(-4, 5):
				xx, yy = x + dx, y + dy
				if (0 <= xx < self._size) and (0 <= yy < self._size):
					# Chebyshev/infinity norm
					self._set_function_module(xx, yy, max(abs(dx), abs(dy)) not in (2, 4))
	
	
	def _draw_alignment_pattern(self, x: int, y: int) -> None:
		"""Draws a 5*5 alignment pattern, with the center module
		at (x, y). All modules must be in bounds."""
		for dy in range(-2, 3):
			for dx in range(-2, 3):
				self._set_function_module(x + dx, y + dy, max(abs(dx), abs(dy)) != 1)
	
	
	def _set_function_module(self, x: int, y: int, isdark: bool) -> None:
		"""Sets the color of a module and marks it as a function module.
		Only used by the constructor. Coordinates must be in bounds."""
		assert type(isdark) is bool
		self._modules[y][x] = isdark
		self._isfunction[y][x] = True
	
	
	# ---- Private helper methods for constructor: Codewords and masking ----
	
	def _add_ecc_and_interleave(self, data: bytearray) -> bytes:
		"""Returns a new byte string representing the given data with the appropriate error correction
		codewords appended to it, based on this object's version and error correction level."""
		version: int = self._version
		assert len(data) == QrCode._get_num_data_codewords(version, self._errcorlvl)
		
		# Calculate parameter numbers
		numblocks: int = QrCode._NUM_ERROR_CORRECTION_BLOCKS[self._errcorlvl.ordinal][version]
		blockecclen: int = QrCode._ECC_CODEWORDS_PER_BLOCK  [self._errcorlvl.ordinal][version]
		rawcodewords: int = QrCode._get_num_raw_data_modules(version) // 8
		numshortblocks: int = numblocks - rawcodewords % numblocks
		shortblocklen: int = rawcodewords // numblocks
		
		# Split data into blocks and append ECC to each block
		blocks: list[bytes] = []
		rsdiv: bytes = QrCode._reed_solomon_compute_divisor(blockecclen)
		k: int = 0
		for i in range(numblocks):
			dat: bytearray = data[k : k + shortblocklen - blockecclen + (0 if i < numshortblocks else 1)]
			k += len(dat)
			ecc: bytes = QrCode._reed_solomon_compute_remainder(dat, rsdiv)
			if i < numshortblocks:
				dat.append(0)
			blocks.append(dat + ecc)
		assert k == len(data)
		
		# Interleave (not concatenate) the bytes from every block into a single sequence
		result = bytearray()
		for i in range(len(blocks[0])):
			for (j, blk) in enumerate(blocks):
				# Skip the padding byte in short blocks
				if (i != shortblocklen - blockecclen) or (j >= numshortblocks):
					result.append(blk[i])
		assert len(result) == rawcodewords
		return result
	
	
	def _draw_codewords(self, data: bytes) -> None:
		"""Draws the given sequence of 8-bit codewords (data and error correction) onto the entire
		data area of this QR Code. Function modules need to be marked off before this is called."""
		assert len(data) == QrCode._get_num_raw_data_modules(self._version) // 8
		
		i: int = 0  # Bit index into the data
		# Do the funny zigzag scan
		for right in range(self._size - 1, 0, -2):  # Index of right column in each column pair
			if right <= 6:
				right -= 1
			for vert in range(self._size):  # Vertical counter
				for j in range(2):
					x: int = right - j  # Actual x coordinate
					upward: bool = (right + 1) & 2 == 0
					y: int = (self._size - 1 - vert) if upward else vert  # Actual y coordinate
					if (not self._isfunction[y][x]) and (i < len(data) * 8):
						self._modules[y][x] = _get_bit(data[i >> 3], 7 - (i & 7))
						i += 1
					# If this QR Code has any remainder bits (0 to 7), they were assigned as
					# 0/false/light by the constructor and are left unchanged by this method
		assert i == len(data) * 8
	
	
	def _apply_mask(self, mask: int) -> None:
		"""XORs the codeword modules in this QR Code with the given mask pattern.
		The function modules must be marked and the codeword bits must be drawn
		before masking. Due to the arithmetic of XOR, calling _apply_mask() with
		the same mask value a second time will undo the mask. A final well-formed
		QR Code needs exactly one (not zero, two, etc.) mask applied."""
		if not (0 <= mask <= 7):
			raise ValueError("Mask value out of range")
		masker: collections.abc.Callable[[int,int],int] = QrCode._MASK_PATTERNS[mask]
		for y in range(self._size):
			for x in range(self._size):
				self._modules[y][x] ^= (masker(x, y) == 0) and (not self._isfunction[y][x])
	
	
	def _get_penalty_score(self) -> int:
		"""Calculates and returns the penalty score based on state of this QR Code's current modules.
		This is used by the automatic mask choice algorithm to find the mask pattern that yields the lowest score."""
		result: int = 0
		size: int = self._size
		modules: list[list[bool]] = self._modules
		
		# Adjacent modules in row having same color, and finder-like patterns
		for y in range(size):
			runcolor: bool = False
			runx: int = 0
			runhistory = collections.deque([0] * 7, 7)
			for x in range(size):
				if modules[y][x] == runcolor:
					runx += 1
					if runx == 5:
						result += QrCode._PENALTY_N1
					elif runx > 5:
						result += 1
				else:
					self._finder_penalty_add_history(runx, runhistory)
					if not runcolor:
						result += self._finder_penalty_count_patterns(runhistory) * QrCode._PENALTY_N3
					runcolor = modules[y][x]
					runx = 1
			result += self._finder_penalty_terminate_and_count(runcolor, runx, runhistory) * QrCode._PENALTY_N3
		# Adjacent modules in column having same color, and finder-like patterns
		for x in range(size):
			runcolor = False
			runy: int = 0
			runhistory = collections.deque([0] * 7, 7)
			for y in range(size):
				if modules[y][x] == runcolor:
					runy += 1
					if runy == 5:
						result += QrCode._PENALTY_N1
					elif runy > 5:
						result += 1
				else:
					self._finder_penalty_add_history(runy, runhistory)
					if not runcolor:
						result += self._finder_penalty_count_patterns(runhistory) * QrCode._PENALTY_N3
					runcolor = modules[y][x]
					runy = 1
			result += self._finder_penalty_terminate_and_count(runcolor, runy, runhistory) * QrCode._PENALTY_N3
		
		# 2*2 blocks of modules having same color
		for y in range(size - 1):
			for x in range(size - 1):
				if modules[y][x] == modules[y][x + 1] == modules[y + 1][x] == modules[y + 1][x + 1]:
					result += QrCode._PENALTY_N2
		
		# Balance of dark and light modules
		dark: int = sum((1 if cell else 0) for row in modules for cell in row)
		total: int = size**2  # Note that size is odd, so dark/total != 1/2
		# Compute the smallest integer k >= 0 such that (45-5k)% <= dark/total <= (55+5k)%
		k: int = (abs(dark * 20 - total * 10) + total - 1) // total - 1
		assert 0 <= k <= 9
		result += k * QrCode._PENALTY_N4
		assert 0 <= result <= 2568888  # Non-tight upper bound based on default values of PENALTY_N1, ..., N4
		return result
	
	
	# ---- Private helper functions ----
	
	def _get_alignment_pattern_positions(self) -> list[int]:
		"""Returns an ascending list of positions of alignment patterns for this version number.
		Each position is in the range [0,177), and are used on both the x and y axes.
		This could be implemented as lookup table of 40 variable-length lists of integers."""
		if self._version == 1:
			return []
		else:
			numalign: int = self._version // 7 + 2
			step: int = (self._version * 8 + numalign * 3 + 5) // (numalign * 4 - 4) * 2
			result: list[int] = [(self._size - 7 - i * step) for i in range(numalign - 1)] + [6]
			return list(reversed(result))
	
	
	@staticmethod
	def _get_num_raw_data_modules(ver: int) -> int:
		"""Returns the number of data bits that can be stored in a QR Code of the given version number, after
		all function modules are excluded. This includes remainder bits, so it might not be a multiple of 8.
		The result is in the range [208, 29648]. This could be implemented as a 40-entry lookup table."""
		if not (QrCode.MIN_VERSION <= ver <= QrCode.MAX_VERSION):
			raise ValueError("Version number out of range")
		result: int = (16 * ver + 128) * ver + 64
		if ver >= 2:
			numalign: int = ver // 7 + 2
			result -= (25 * numalign - 10) * numalign - 55
			if ver >= 7:
				result -= 36
		assert 208 <= result <= 29648
		return result
	
	
	@staticmethod
	def _get_num_data_codewords(ver: int, ecl: QrCode.Ecc) -> int:
		"""Returns the number of 8-bit data (i.e. not error correction) codewords contained in any
		QR Code of the given version number and error correction level, with remainder bits discarded.
		This stateless pure function could be implemented as a (40*4)-cell lookup table."""
		return QrCode._get_num_raw_data_modules(ver) // 8 \
			- QrCode._ECC_CODEWORDS_PER_BLOCK    [ecl.ordinal][ver] \
			* QrCode._NUM_ERROR_CORRECTION_BLOCKS[ecl.ordinal][ver]
	
	
	@staticmethod
	def _reed_solomon_compute_divisor(degree: int) -> bytes:
		"""Returns a Reed-Solomon ECC generator polynomial for the given degree. This could be
		implemented as a lookup table over all possible parameter values, instead of as an algorithm."""
		if not (1 <= degree <= 255):
			raise ValueError("Degree out of range")
		# Polynomial coefficients are stored from highest to lowest power, excluding the leading term which is always 1.
		# For example the polynomial x^3 + 255x^2 + 8x + 93 is stored as the uint8 array [255, 8, 93].
		result = bytearray([0] * (degree - 1) + [1])  # Start off with the monomial x^0
		
		# Compute the product polynomial (x - r^0) * (x - r^1) * (x - r^2) * ... * (x - r^{degree-1}),
		# and drop the highest monomial term which is always 1x^degree.
		# Note that r = 0x02, which is a generator element of this field GF(2^8/0x11D).
		root: int = 1
		for _ in range(degree):  # Unused variable i
			# Multiply the current product by (x - r^i)
			for j in range(degree):
				result[j] = QrCode._reed_solomon_multiply(result[j], root)
				if j + 1 < degree:
					result[j] ^= result[j + 1]
			root = QrCode._reed_solomon_multiply(root, 0x02)
		return result
	
	
	@staticmethod
	def _reed_solomon_compute_remainder(data: bytes, divisor: bytes) -> bytes:
		"""Returns the Reed-Solomon error correction codeword for the given data and divisor polynomials."""
		result = bytearray([0] * len(divisor))
		for b in data:  # Polynomial division
			factor: int = b ^ result.pop(0)
			result.append(0)
			for (i, coef) in enumerate(divisor):
				result[i] ^= QrCode._reed_solomon_multiply(coef, factor)
		return result
	
	
	@staticmethod
	def _reed_solomon_multiply(x: int, y: int) -> int:
		"""Returns the product of the two given field elements modulo GF(2^8/0x11D). The arguments and result
		are unsigned 8-bit integers. This could be implemented as a lookup table of 256*256 entries of uint8."""
		if (x >> 8 != 0) or (y >> 8 != 0):
			raise ValueError("Byte out of range")
		# Russian peasant multiplication
		z: int = 0
		for i in reversed(range(8)):
			z = (z << 1) ^ ((z >> 7) * 0x11D)
			z ^= ((y >> i) & 1) * x
		assert z >> 8 == 0
		return z
	
	
	def _finder_penalty_count_patterns(self, runhistory: collections.deque[int]) -> int:
		"""Can only be called immediately after a light run is added, and
		returns either 0, 1, or 2. A helper function for _get_penalty_score()."""
		n: int = runhistory[1]
		assert n <= self._size * 3
		core: bool = n > 0 and (runhistory[2] == runhistory[4] == runhistory[5] == n) and runhistory[3] == n * 3
		return (1 if (core and runhistory[0] >= n * 4 and runhistory[6] >= n) else 0) \
		     + (1 if (core and runhistory[6] >= n * 4 and runhistory[0] >= n) else 0)
	
	
	def _finder_penalty_terminate_and_count(self, currentruncolor: bool, currentrunlength: int, runhistory: collections.deque[int]) -> int:
		"""Must be called at the end of a line (row or column) of modules. A helper function for _get_penalty_score()."""
		if currentruncolor:  # Terminate dark run
			self._finder_penalty_add_history(currentrunlength, runhistory)
			currentrunlength = 0
		currentrunlength += self._size  # Add light border to final run
		self._finder_penalty_add_history(currentrunlength, runhistory)
		return self._finder_penalty_count_patterns(runhistory)
	
	
	def _finder_penalty_add_history(self, currentrunlength: int, runhistory: collections.deque[int]) -> None:
		if runhistory[0] == 0:
			currentrunlength += self._size  # Add light border to initial run
		runhistory.appendleft(currentrunlength)
	
	
	# ---- Constants and tables ----
	
	MIN_VERSION: int =  1  # The minimum version number supported in the QR Code Model 2 standard
	MAX_VERSION: int = 40  # The maximum version number supported in the QR Code Model 2 standard
	
	# For use in _get_penalty_score(), when evaluating which mask is best.
	_PENALTY_N1: int =  3
	_PENALTY_N2: int =  3
	_PENALTY_N3: int = 40
	_PENALTY_N4: int = 10
	
	_ECC_CODEWORDS_PER_BLOCK: Sequence[Sequence[int]] = (
		# Version: (note that index 0 is for padding, and is set to an illegal value)
		# 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40    Error correction level
		(-1,  7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),  # Low
		(-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28),  # Medium
		(-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),  # Quartile
		(-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30))  # High
	
	_NUM_ERROR_CORRECTION_BLOCKS: Sequence[Sequence[int]] = (
		# Version: (note that index 0 is for padding, and is set to an illegal value)
		# 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40    Error correction level
		(-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4,  4,  4,  4,  4,  6,  6,  6,  6,  7,  8,  8,  9,  9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25),  # Low
		(-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5,  5,  8,  9,  9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49),  # Medium
		(-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8,  8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68),  # Quartile
		(-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81))  # High
	
	_MASK_PATTERNS: Sequence[collections.abc.Callable[[int,int],int]] = (
		(lambda x, y:  (x + y) % 2                  ),
		(lambda x, y:  y % 2                        ),
		(lambda x, y:  x % 3                        ),
		(lambda x, y:  (x + y) % 3                  ),
		(lambda x, y:  (x // 3 + y // 2) % 2        ),
		(lambda x, y:  x * y % 2 + x * y % 3        ),
		(lambda x, y:  (x * y % 2 + x * y % 3) % 2  ),
		(lambda x, y:  ((x + y) % 2 + x * y % 3) % 2),
	)
	
	
	# ---- Public helper enumeration ----
	
	class Ecc:
		ordinal: int  # (Public) In the range 0 to 3 (unsigned 2-bit integer)
		formatbits: int  # (Package-private) In the range 0 to 3 (unsigned 2-bit integer)
		
		"""The error correction level in a QR Code symbol. Immutable."""
		# Private constructor
		def __init__(self, i: int, fb: int) -> None:
			self.ordinal = i
			self.formatbits = fb
		
		# Placeholders
		LOW     : QrCode.Ecc
		MEDIUM  : QrCode.Ecc
		QUARTILE: QrCode.Ecc
		HIGH    : QrCode.Ecc
	
	# Public constants. Create them outside the class.
	Ecc.LOW      = Ecc(0, 1)  # The QR Code can tolerate about  7% erroneous codewords
	Ecc.MEDIUM   = Ecc(1, 0)  # The QR Code can tolerate about 15% erroneous codewords
	Ecc.QUARTILE = Ecc(2, 3)  # The QR Code can tolerate about 25% erroneous codewords
	Ecc.HIGH     = Ecc(3, 2)  # The QR Code can tolerate about 30% erroneous codewords



# ---- Data segment class ----

class QrSegment:
	"""A segment of character/binary/control data in a QR Code symbol.
	Instances of this class are immutable.
	The mid-level way to create a segment is to take the payload data
	and call a static factory function such as QrSegment.make_numeric().
	The low-level way to create a segment is to custom-make the bit buffer
	and call the QrSegment() constructor with appropriate values.
	This segment class imposes no length restrictions, but QR Codes have restrictions.
	Even in the most favorable conditions, a QR Code can only hold 7089 characters of data.
	Any segment longer than this is meaningless for the purpose of generating QR Codes."""
	
	# ---- Static factory functions (mid level) ----
	
	@staticmethod
	def make_bytes(data: Union[bytes,Sequence[int]]) -> QrSegment:
		"""Returns a segment representing the given binary data encoded in byte mode.
		All input byte lists are acceptable. Any text string can be converted to
		UTF-8 bytes (s.encode("UTF-8")) and encoded as a byte mode segment."""
		bb = _BitBuffer()
		for b in data:
			bb.append_bits(b, 8)
		return QrSegment(QrSegment.Mode.BYTE, len(data), bb)
	
	
	@staticmethod
	def make_numeric(digits: str) -> QrSegment:
		"""Returns a segment representing the given string of decimal digits encoded in numeric mode."""
		if not QrSegment.is_numeric(digits):
			raise ValueError("String contains non-numeric characters")
		bb = _BitBuffer()
		i: int = 0
		while i < len(digits):  # Consume up to 3 digits per iteration
			n: int = min(len(digits) - i, 3)
			bb.append_bits(int(digits[i : i + n]), n * 3 + 1)
			i += n
		return QrSegment(QrSegment.Mode.NUMERIC, len(digits), bb)
	
	
	@staticmethod
	def make_alphanumeric(text: str) -> QrSegment:
		"""Returns a segment representing the given text string encoded in alphanumeric mode.
		The characters allowed are: 0 to 9, A to Z (uppercase only), space,
		dollar, percent, asterisk, plus, hyphen, period, slash, colon."""
		if not QrSegment.is_alphanumeric(text):
			raise ValueError("String contains unencodable characters in alphanumeric mode")
		bb = _BitBuffer()
		for i in range(0, len(text) - 1, 2):  # Process groups of 2
			temp: int = QrSegment._ALPHANUMERIC_ENCODING_TABLE[text[i]] * 45
			temp += QrSegment._ALPHANUMERIC_ENCODING_TABLE[text[i + 1]]
			bb.append_bits(temp, 11)
		if len(text) % 2 > 0:  # 1 character remaining
			bb.append_bits(QrSegment._ALPHANUMERIC_ENCODING_TABLE[text[-1]], 6)
		return QrSegment(QrSegment.Mode.ALPHANUMERIC, len(text), bb)
	
	
	@staticmethod
	def make_segments(text: str) -> list[QrSegment]:
		"""Returns a new mutable list of zero or more segments to represent the given Unicode text string.
		The result may use various segment modes and switch modes to optimize the length of the bit stream."""
		
		# Select the most efficient segment encoding automatically
		if text == "":
			return []
		elif QrSegment.is_numeric(text):
			return [QrSegment.make_numeric(text)]
		elif QrSegment.is_alphanumeric(text):
			return [QrSegment.make_alphanumeric(text)]
		else:
			return [QrSegment.make_bytes(text.encode("UTF-8"))]
	
	
	# Tests whether the given string can be encoded as a segment in numeric mode.
	# A string is encodable iff each character is in the range 0 to 9.
	@staticmethod
	def is_numeric(text: str) -> bool:
		return QrSegment._NUMERIC_REGEX.fullmatch(text) is not None
	
	
	# Tests whether the given string can be encoded as a segment in alphanumeric mode.
	# A string is encodable iff each character is in the following set: 0 to 9, A to Z
	# (uppercase only), space, dollar, percent, asterisk, plus, hyphen, period, slash, colon.
	@staticmethod
	def is_alphanumeric(text: str) -> bool:
		return QrSegment._ALPHANUMERIC_REGEX.fullmatch(text) is not None
	
	
	# ---- Private fields ----
	
	# The mode indicator of this segment. Accessed through get_mode().
	_mode: QrSegment.Mode
	
	# The length of this segment's unencoded data. Measured in characters for
	# numeric/alphanumeric/kanji mode, bytes for byte mode, and 0 for ECI mode.
	# Always zero or positive. Not the same as the data's bit length.
	# Accessed through get_num_chars().
	_numchars: int
	
	# The data bits of this segment. Accessed through get_data().
	_bitdata: list[int]
	
	
	# ---- Constructor (low level) ----
	
	def __init__(self, mode: QrSegment.Mode, numch: int, bitdata: Sequence[int]) -> None:
		"""Creates a new QR Code segment with the given attributes and data.
		The character count (numch) must agree with the mode and the bit buffer length,
		but the constraint isn't checked. The given bit buffer is cloned and stored."""
		if numch < 0:
			raise ValueError()
		self._mode = mode
		self._numchars = numch
		self._bitdata = list(bitdata)  # Make defensive copy
	
	
	# ---- Accessor methods ----
	
	def get_mode(self) -> QrSegment.Mode:
		"""Returns the mode field of this segment."""
		return self._mode
	
	def get_num_chars(self) -> int:
		"""Returns the character count field of this segment."""
		return self._numchars
	
	def get_data(self) -> list[int]:
		"""Returns a new copy of the data bits of this segment."""
		return list(self._bitdata)  # Make defensive copy
	
	
	# Package-private function
	@staticmethod
	def get_total_bits(segs: Sequence[QrSegment], version: int) -> Optional[int]:
		"""Calculates the number of bits needed to encode the given segments at
		the given version. Returns a non-negative number if successful. Otherwise
		returns None if a segment has too many characters to fit its length field."""
		result = 0
		for seg in segs:
			ccbits: int = seg.get_mode().num_char_count_bits(version)
			if seg.get_num_chars() >= (1 << ccbits):
				return None  # The segment's length doesn't fit the field's bit width
			result += 4 + ccbits + len(seg._bitdata)
		return result
	
	
	# ---- Constants ----
	
	# Describes precisely all strings that are encodable in numeric mode.
	_NUMERIC_REGEX: re.Pattern[str] = re.compile(r"[0-9]*")
	
	# Describes precisely all strings that are encodable in alphanumeric mode.
	_ALPHANUMERIC_REGEX: re.Pattern[str] = re.compile(r"[A-Z0-9 $%*+./:-]*")
	
	# Dictionary of "0"->0, "A"->10, "$"->37, etc.
	_ALPHANUMERIC_ENCODING_TABLE: dict[str,int] = {ch: i for (i, ch) in enumerate("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:")}
	
	
	# ---- Public helper enumeration ----
	
	class Mode:
		"""Describes how a segment's data bits are interpreted. Immutable."""
		
		_modebits: int  # The mode indicator bits, which is a uint4 value (range 0 to 15)
		_charcounts: tuple[int,int,int]  # Number of character count bits for three different version ranges
		
		# Private constructor
		def __init__(self, modebits: int, charcounts: tuple[int,int,int]):
			self._modebits = modebits
			self._charcounts = charcounts
		
		# Package-private method
		def get_mode_bits(self) -> int:
			"""Returns an unsigned 4-bit integer value (range 0 to 15) representing the mode indicator bits for this mode object."""
			return self._modebits
		
		# Package-private method
		def num_char_count_bits(self, ver: int) -> int:
			"""Returns the bit width of the character count field for a segment in this mode
			in a QR Code at the given version number. The result is in the range [0, 16]."""
			return self._charcounts[(ver + 7) // 17]
		
		# Placeholders
		NUMERIC     : QrSegment.Mode
		ALPHANUMERIC: QrSegment.Mode
		BYTE        : QrSegment.Mode
	
	# Public constants. Create them outside the class.
	Mode.NUMERIC      = Mode(0x1, (10, 12, 14))
	Mode.ALPHANUMERIC = Mode(0x2, ( 9, 11, 13))
	Mode.BYTE         = Mode(0x4, ( 8, 16, 16))



# ---- Private helper class ----

class _BitBuffer(list[int]):
	"""An appendable sequence of bits (0s and 1s). Mainly used by QrSegment."""
	
	def append_bits(self, val: int, n: int) -> None:
		"""Appends the given number of low-order bits of the given
		value to this buffer. Requires n >= 0 and 0 <= val < 2^n."""
		if (n < 0) or (val >> n != 0):
			raise ValueError("Value out of range")
		self.extend(((val >> i) & 1) for i in reversed(range(n)))


def _get_bit(x: int, i: int) -> bool:
	"""Returns true iff the i'th bit of x is set to 1."""
	return (x >> i) & 1 != 0



class DataTooLongError(ValueError):
	"""Raised when the supplied text does not fit in any QR Code version (up to
	version 40, the format's maximum size) -- not expected in practice for the
	short PEM keys FSS encodes into a QR code."""
	pass

try:
    import fss_core_1_1_0 as core
except ImportError:
    sys.exit(
        "Could not find fss_core_1_1_0.py.\n"
        "FileSecureSuite_2_0_0.py must sit in the same folder as fss_core_1_1_0.py — copy both "
        "files together."
    )

try:
    from PySide6.QtCore import Qt, QThread, Signal, QObject, QUrl, QTimer
    from PySide6.QtGui import (QGuiApplication, QDragEnterEvent, QDropEvent,
                               QFont, QDesktopServices, QImage, QPixmap)
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
        QPushButton, QFileDialog, QLineEdit, QComboBox, QButtonGroup, QFrame,
        QProgressBar, QToolButton, QStackedWidget, QScrollArea, QPlainTextEdit,
        QSplitter, QMessageBox, QSizePolicy,
    )
except ImportError:
    sys.exit(
        "PySide6 is not installed.\n"
        "Install it with:  pip install PySide6 cryptography\n"
        "then run this file again: python FileSecureSuite_2_0_0.py"
    )


def _app_data_dir() -> str:
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


APP_DIR = _app_data_dir()
FILES_DIR = os.path.join(APP_DIR, 'files')
KEYS_DIR = os.path.join(APP_DIR, 'keys')
TEXTS_DIR = os.path.join(APP_DIR, 'texts')
BACKUP_DIR = os.path.join(APP_DIR, 'backup')
LOG_DIR = os.path.join(APP_DIR, 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'encryption_audit.log')

CREDITS_LNURL = ('lnurl1dp68gurn8ghj7ampd3kx2ar0veekzar0wd5xjtnrdakj7tnhv4kxctttdehhw'
                 'm30d3h82unvwqhk6ctjd9skummcxu6qs3rtcq')
CREDITS_QR_MATRIX = (
    '11111110001010100001110100001011101111111', '10000010010000000010000001011110001000001',
    '10111010111000000001111110101000101011101', '10111010111010101011100001111100001011101',
    '10111010110101110011011101100011101011101', '10000010101011010110001011110100001000001',
    '11111110101010101010101010101010101111111', '00000000110010001001011100011011000000000',
    '10111110011010010101101101010111101111100', '00010100010000010011010110101001011111111',
    '11001010110011001100000010110010000010000', '10000000110111010000110110100000010001010',
    '01001111001111010100101101110100100000111', '11001001001110100001100101101001111110001',
    '10111010111000011100110000111000101001000', '00011101110000000011010010111010010111010',
    '10010011000100100100000001001101110001111', '00101100000101000101111111101111101111011',
    '10001011111000001100100010010110000000100', '11110101111001000110111000010000100010011',
    '11010011111100010000001011100100100101110', '10000100111110011111111101101101111110111',
    '11011011100000101110110010011010110101100', '00101000000000001001011000001011001010010',
    '11110010000101100101001011111101100101111', '10100000001000100001110101001011101111111',
    '11001111001110001000011010011110011100100', '01001101110110110010010010011010111001000',
    '10000111110110011100001101110110100101110', '11110000001000001011100100001001011110011',
    '10100011110001110100010011011000010010100', '10010101011111101000110100111000100010011',
    '10111110111111101100100011000100111111101', '00000000100111111001111100101011100011001',
    '11111110000100100010000010110001101010010', '10000010100010110001010010110001100011010',
    '10111010111011011010001001001100111110111', '10111010111111011101101100101010000101011',
    '10111010101000101000111011110101011110100', '10000010010001011010011110110000100111010',
    '11111110100111010000101111111101000110100',
)


def _flash_button_text(button: QPushButton, temporary_text: str, delay_ms: int = 2000):
    """Show temporary_text on a button (e.g. after 'Copy' or 'Save'), then
    restore whatever text it had right before this call - unless something
    else already changed it in the meantime."""
    original_text = button.text()
    button.setText(temporary_text)
    QTimer.singleShot(delay_ms, lambda: button.setText(original_text)
                       if button.text() == temporary_text else None)


def open_folder(path: str):
    """Create and open one of the suite's output folders."""
    core.ensure_private_directory(path)
    if not QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(path))):
        raise CryptoError(f'Could not open the folder: {path}')


def log_operation(operation: str, filepath: str, method: str, status: str,
                   file_hash: str = "", error: str = "", additional: str = "",
                   key_fingerprint: str = "", keyname: str = ""):
    """Write a privacy-minimized audit entry without names or content."""
    try:
        core.ensure_private_directory(LOG_DIR)
        # Keep the legacy nine-field format, but deliberately leave the file-name
        # and key-name fields empty. The fingerprint identifies the public key
        # without associating it with a person or document name.
        fields = [datetime.datetime.now().isoformat(), operation,
                  '', method, status, '',
                  key_fingerprint, additional, error]
        entry = ' | '.join(
            core.safe_display(str(v)).replace('\n', '\\n').replace('\t', '\\t')
                .replace('|', '\\|')[:200]
            for v in fields
        ) + '\n'
        core.reject_links(LOG_FILE)
        try:
            fd = core.protect_path(LOG_FILE, create_file=True)
        except FileExistsError:
            core.protect_path(LOG_FILE)
            flags = os.O_WRONLY | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0)
            fd = os.open(LOG_FILE, flags)
        with os.fdopen(fd, 'a', encoding='utf-8') as f:
            f.write(entry)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        pass  # Audit logging is best-effort; never block a real operation on it.


def _write_atomic(path: str, data: bytes):
    path = os.path.abspath(path)
    core.reject_links(path)
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    candidate = os.path.join(directory, '.fss-' + secrets.token_hex(16) + '.tmp')
    try:
        fd = core.protect_path(candidate, create_file=True)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        core.reject_links(path)
        os.replace(candidate, path)
        candidate = None
    finally:
        if candidate:
            try:
                info = os.lstat(candidate)
                if stat.S_ISREG(info.st_mode):
                    os.unlink(candidate)
            except FileNotFoundError:
                pass
            except OSError:
                pass


def _cleanup_stale_temp_files(max_age_seconds: int = 24 * 60 * 60):
    """Remove only old temporary files created by this suite in its own folders."""
    cutoff = time.time() - max_age_seconds
    pattern = re.compile(r'^\.fss-[0-9a-f]{32}\.tmp$')
    for directory in (FILES_DIR, KEYS_DIR, TEXTS_DIR, BACKUP_DIR, LOG_DIR):
        if not os.path.isdir(directory):
            continue
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        for name in names:
            if not pattern.fullmatch(name):
                continue
            path = os.path.join(directory, name)
            try:
                info = os.lstat(path)
                if stat.S_ISREG(info.st_mode) and info.st_mtime < cutoff:
                    os.unlink(path)
            except OSError:
                pass


def export_base64_copy(source_path: str, output_path: str) -> dict:
    """Encode an encrypted file to Base64 in small chunks and save atomically."""
    source_path = os.path.abspath(source_path)
    output_path = os.path.abspath(output_path)
    core.reject_links(source_path)
    source_info = os.stat(source_path)
    if (not stat.S_ISREG(source_info.st_mode)
            or source_info.st_size > core.MAX_ENCRYPTED_SIZE):
        raise CryptoError('The encrypted source file is invalid or too large.')

    directory = os.path.dirname(output_path)
    if os.path.normcase(os.path.realpath(directory)) == os.path.normcase(os.path.realpath(FILES_DIR)):
        core.ensure_private_directory(directory)
    else:
        core.reject_links(directory)
        if not os.path.isdir(directory):
            raise CryptoError('Choose an existing output folder.')
    core.reject_links(output_path)
    candidate = os.path.join(directory, '.fss-' + secrets.token_hex(16) + '.tmp')
    source_flags = (os.O_RDONLY | getattr(os, 'O_BINARY', 0)
                    | getattr(os, 'O_NOFOLLOW', 0))
    source_fd = os.open(source_path, source_flags)
    target_fd = None
    try:
        target_fd = core.protect_path(candidate, create_file=True)
        with os.fdopen(source_fd, 'rb') as source, os.fdopen(target_fd, 'wb') as target:
            source_fd = -1
            target_fd = None
            opened_info = os.fstat(source.fileno())
            if (not stat.S_ISREG(opened_info.st_mode)
                    or opened_info.st_size != source_info.st_size):
                raise CryptoError('The encrypted source file changed during export.')
            # A multiple of 3 preserves Base64 block boundaries between chunks.
            while True:
                chunk = source.read(3 * 1024 * 1024)
                if not chunk:
                    break
                target.write(base64.b64encode(chunk))
            target.flush()
            os.fsync(target.fileno())
        core.reject_links(output_path)
        os.replace(candidate, output_path)
    except Exception:
        try:
            if os.path.exists(candidate):
                os.unlink(candidate)
        except OSError:
            pass
        raise
    finally:
        if source_fd != -1:
            os.close(source_fd)
        if target_fd is not None:
            os.close(target_fd)
    return {'path': output_path}


def public_key_qr_png(public_pem: str, module_size: int = 5) -> bytes:
    """Return a PNG QR code containing the complete public-key PEM."""
    qr = QrCode.encode_text(public_pem, QrCode.Ecc.LOW)
    quiet_zone = 4
    qr_size = qr.get_size()
    image_size = (qr_size + quiet_zone * 2) * module_size
    pixels = bytearray()
    for y in range(image_size):
        pixels.append(0)  # PNG scanline filter: None
        qr_y = y // module_size - quiet_zone
        for x in range(image_size):
            qr_x = x // module_size - quiet_zone
            dark = (0 <= qr_x < qr_size and 0 <= qr_y < qr_size
                    and qr.get_module(qr_x, qr_y))
            pixels.append(0 if dark else 255)

    def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
        checksum = zlib.crc32(chunk_type + data) & 0xffffffff
        return struct.pack('>I', len(data)) + chunk_type + data + struct.pack('>I', checksum)

    header = struct.pack('>IIBBBBB', image_size, image_size, 8, 0, 0, 0, 0)
    return (b'\x89PNG\r\n\x1a\n'
            + png_chunk(b'IHDR', header)
            + png_chunk(b'IDAT', zlib.compress(bytes(pixels), 9))
            + png_chunk(b'IEND', b''))


def suggest_output_path(original_name: str, encrypted_extension: str = '',
                         fingerprint: str = '') -> str:
    """Return a readable, collision-free path in FILES_DIR."""
    core.ensure_private_directory(FILES_DIR)
    name = core.output_basename(original_name)
    marker = '_' + fingerprint[:12].upper() if fingerprint else ''
    if encrypted_extension:
        stem, suffix = name + marker, '.' + encrypted_extension
    else:
        stem, suffix = os.path.splitext(name)
        stem += marker
    base = os.path.normcase(os.path.realpath(FILES_DIR))
    for number in range(10000):
        counter = f' ({number})' if number else ''
        candidate = os.path.join(FILES_DIR, stem + counter + suffix)
        if os.path.normcase(os.path.realpath(os.path.dirname(candidate))) != base:
            raise ValueError('Output is outside the allowed directory')
        if not os.path.lexists(candidate):
            return candidate
    raise ValueError('Too many files with the same output name')


def suggest_text_path(encrypted_extension: str = '') -> str:
    core.ensure_private_directory(TEXTS_DIR)
    stamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    suffix = '.' + encrypted_extension if encrypted_extension else '.txt'
    for number in range(10000):
        counter = f' ({number})' if number else ''
        candidate = os.path.join(TEXTS_DIR, f'text_{stamp}{counter}{suffix}')
        if not os.path.lexists(candidate):
            return candidate
    raise ValueError('Too many text files with the same name.')


def backup_keys(selected_paths: Optional[list] = None,
                destination_dir: Optional[str] = None) -> dict:
    """Back up every PEM key, or only the explicitly selected key files."""
    core.ensure_private_directory(KEYS_DIR)
    destination_dir = os.path.abspath(destination_dir or BACKUP_DIR)
    if os.path.normcase(os.path.realpath(destination_dir)) == os.path.normcase(os.path.realpath(BACKUP_DIR)):
        core.ensure_private_directory(destination_dir)
    else:
        core.reject_links(destination_dir)
        if not os.path.isdir(destination_dir):
            raise CryptoError('Choose an existing backup folder.')
    if selected_paths is None:
        selected_paths = [os.path.join(KEYS_DIR, name) for name in os.listdir(KEYS_DIR)
                          if name.lower().endswith('.pem')]
    if not selected_paths:
        raise CryptoError('No RSA keys were found or selected.')
    saved = []
    for source in selected_paths:
        source = os.path.abspath(source)
        source_parent = os.path.normcase(os.path.realpath(os.path.dirname(source)))
        keys_parent = os.path.normcase(os.path.realpath(KEYS_DIR))
        if source_parent != keys_parent or not source.lower().endswith('.pem'):
            raise CryptoError('Only keys from the application keys folder can be backed up.')
        data = core.read_limited(source, core.MAX_KEY_SIZE)
        stem, extension = os.path.splitext(os.path.basename(source))
        for _ in range(100):
            destination = os.path.join(
                destination_dir, f'{stem}_copy_{secrets.token_hex(8)}{extension}')
            if not os.path.lexists(destination):
                break
        else:
            raise CryptoError('Could not choose a unique backup filename.')
        _write_atomic(destination, data)
        saved.append(destination)
    log_operation('BACKUP', destination_dir, 'RSA', 'SUCCESS',
                  additional=f'Backed up {len(saved)} key(s)')
    return {'files': saved, 'count': len(saved), 'directory': destination_dir}


def export_public_key(private_path: str, password: Optional[str] = None) -> dict:
    """Extract an interoperable public PEM key from a private PEM key."""
    try:
        private_pem = core.read_limited(private_path, core.MAX_KEY_SIZE).decode('utf-8')
        private_key = core.serialization.load_pem_private_key(
            private_pem.encode('utf-8'), password.encode('utf-8') if password else None)
        core.require_rsa_key(private_key)
    except (OSError, ValueError, TypeError) as e:
        raise CryptoError(f'Could not unlock the private key: {e}')
    public_pem = private_key.public_key().public_bytes(
        encoding=core.serialization.Encoding.PEM,
        format=core.serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint = core.calculate_key_fingerprint(public_pem.decode('utf-8'), is_public=True)
    core.ensure_private_directory(BACKUP_DIR)
    keyname = os.path.splitext(os.path.basename(private_path))[0].replace('_private', '')
    filename = core.get_unique_filename(keyname + '_public_exported', 'pem')
    destination = os.path.join(BACKUP_DIR, filename)
    _write_atomic(destination, public_pem)
    log_operation('EXPORT', destination, 'RSA', 'SUCCESS', key_fingerprint=fingerprint,
                  additional='export_public_key (gui)')
    return {'data': public_pem, 'path': destination, 'fingerprint': fingerprint}


def get_audit_log() -> str:
    try:
        return core.read_limited(LOG_FILE, core.MAX_TEXT_SIZE).decode('utf-8', errors='replace')
    except FileNotFoundError:
        return 'No audit entries yet.'
    except (OSError, ValueError) as e:
        return f'Could not read the audit log: {e}'


class CryptoError(Exception):
    """A message that is always safe to show as-is in the UI."""


def encrypt_file(filepath: str, method: str, *, password: Optional[str] = None,
                  public_key_pem: Optional[str] = None) -> dict:
    if not os.path.exists(filepath):
        raise CryptoError('File not found.')
    size = os.path.getsize(filepath)
    if size == 0:
        raise CryptoError('File is empty.')
    if size > core.MAX_FILE_SIZE:
        raise CryptoError(f'File too large (max {core.format_size(core.MAX_FILE_SIZE)}).')
    try:
        core.check_available_memory(size)
    except ValueError as e:
        raise CryptoError(str(e))

    data = core.read_limited(filepath, core.MAX_FILE_SIZE)
    original_filename = core.output_basename(os.path.basename(filepath))
    if len(original_filename.encode('utf-8')) > 254:
        raise CryptoError('Filename is too long (254-byte limit) — rename the file and try again.')
    payload = original_filename.encode('utf-8') + b'\x00' + data
    file_hash = hashlib.sha256(payload).hexdigest()

    if method == 'aes':
        valid, msg = core.validate_password_strength(password or '')
        if not valid:
            raise CryptoError(msg)
        encrypted = core.aes_encrypt_with_hash(payload, password, file_hash, payload_type=1)
        suggested = suggest_output_path(original_filename, 'aes')
        base64_path = suggest_output_path(original_filename, 'aes.b64')
        return {'data': encrypted, 'suggested_path': suggested, 'fingerprint': None,
                'base64_path': base64_path,
                'audit': {'operation': 'ENCRYPT', 'method': 'AES-256',
                          'file_hash': file_hash, 'additional': 'encrypt_file (gui)'}}

    if not public_key_pem or not core.validate_rsa_key(public_key_pem, is_public=True):
        raise CryptoError('Invalid or unreadable public key.')
    fingerprint = core.calculate_key_fingerprint(public_key_pem, is_public=True)
    encrypted = core.rsa_encrypt_hybrid_with_hash(payload, public_key_pem, file_hash, payload_type=1)
    suggested = suggest_output_path(original_filename, 'rsa', fingerprint)
    base64_path = suggest_output_path(original_filename, 'rsa.b64', fingerprint)
    return {'data': encrypted, 'suggested_path': suggested, 'fingerprint': fingerprint,
            'base64_path': base64_path,
            'audit': {'operation': 'ENCRYPT', 'method': 'RSA',
                      'file_hash': file_hash, 'key_fingerprint': fingerprint,
                      'additional': 'encrypt_file (gui)'}}


def decrypt_file(filepath: str, fallback_method: str, *, password: Optional[str] = None,
                  private_key_pem: Optional[str] = None, key_password: Optional[str] = None) -> dict:
    if not os.path.exists(filepath):
        raise CryptoError('File not found.')
    try:
        core.check_available_memory(os.path.getsize(filepath))
        encrypted_data = core.decode_container(core.read_limited(filepath, core.MAX_ENCODED_SIZE))
    except Exception as e:
        raise CryptoError(f'Read error: {e}')

    fmt = core.detect_payload_format(encrypted_data, filepath) or fallback_method
    if fmt not in ('aes', 'rsa'):
        raise CryptoError('Could not tell whether this is AES- or RSA-encrypted.')

    if fmt == 'aes':
        if not password:
            raise CryptoError('Password required.')
        try:
            plaintext, stored_hash = core.aes_decrypt_with_hash(encrypted_data, password)
        except ValueError:
            log_operation('DECRYPT', filepath, 'AES-256', 'FAILED',
                           error='Wrong password or damaged data', additional='decrypt_file (gui)')
            raise CryptoError('Wrong password, or the file is corrupted.')
        computed_hash = hashlib.sha256(plaintext).hexdigest()
        if not core.verify_hash_constant_time(stored_hash, computed_hash):
            log_operation('DECRYPT', filepath, 'AES-256', 'FAILED', error='Integrity check failed', additional='decrypt_file (gui)')
            raise CryptoError('Integrity check failed — the file may be corrupted.')
        original_name, plaintext = core.recover_file_payload(plaintext, encrypted_data, filepath)
        suggested = suggest_output_path(original_name)
        return {'data': plaintext, 'suggested_path': suggested, 'fingerprint': None,
                'audit': {'operation': 'DECRYPT', 'method': 'AES-256',
                          'file_hash': stored_hash, 'additional': 'decrypt_file (gui)'}}

    if not private_key_pem:
        raise CryptoError('Private key required.')
    if not core.looks_like_private_key_pem(private_key_pem):
        raise CryptoError('That file does not look like a private key. Did you select the public key by mistake?')
    try:
        plaintext, stored_hash = core.rsa_decrypt_hybrid_with_hash(
            encrypted_data, private_key_pem, key_password, filepath)
    except core.KeyFormatError as e:
        log_operation('DECRYPT', filepath, 'RSA', 'FAILED',
                       error='Key problem: ' + str(e), additional='decrypt_file (gui)')
        raise CryptoError(str(e))
    except ValueError:
        log_operation('DECRYPT', filepath, 'RSA', 'FAILED',
                       error='Wrong key or damaged data', additional='decrypt_file (gui)')
        raise CryptoError(
            'This private key does not match the key used to encrypt this file '
            '(or the file is damaged).')
    computed_hash = hashlib.sha256(plaintext).hexdigest()
    if not core.verify_hash_constant_time(stored_hash, computed_hash):
        log_operation('DECRYPT', filepath, 'RSA', 'FAILED', error='Integrity check failed', additional='decrypt_file (gui)')
        raise CryptoError('Integrity check failed — the file may be corrupted, or this is the wrong key.')
    fingerprint = core.calculate_key_fingerprint(private_key_pem, is_public=False, key_password=key_password)
    original_name, plaintext = core.recover_file_payload(plaintext, encrypted_data, filepath)
    suggested = suggest_output_path(original_name, fingerprint=fingerprint)
    return {'data': plaintext, 'suggested_path': suggested, 'fingerprint': fingerprint,
            'audit': {'operation': 'DECRYPT', 'method': 'RSA',
                      'file_hash': stored_hash, 'key_fingerprint': fingerprint,
                      'additional': 'decrypt_file (gui)'}}


def encrypt_text(text: str, method: str, *, password: Optional[str] = None,
                 public_key_pem: Optional[str] = None) -> dict:
    data = text.encode('utf-8')
    if not data:
        raise CryptoError('Enter the text to encrypt.')
    if len(data) > core.MAX_TEXT_SIZE:
        raise CryptoError(f'Text is too large (max {core.format_size(core.MAX_TEXT_SIZE)}).')
    digest = hashlib.sha256(data).hexdigest()

    if method == 'aes':
        valid, message = core.validate_password_strength(password or '')
        if not valid:
            raise CryptoError(message)
        encrypted = core.aes_encrypt_with_hash(data, password, digest, payload_type=0)
        fingerprint = None
    else:
        if not public_key_pem or not core.validate_rsa_key(public_key_pem, is_public=True):
            raise CryptoError('Invalid or unreadable public key.')
        fingerprint = core.calculate_key_fingerprint(public_key_pem, is_public=True)
        encrypted = core.rsa_encrypt_hybrid_with_hash(
            data, public_key_pem, digest, payload_type=0)

    encoded = base64.b64encode(encrypted).decode('ascii')
    path = suggest_text_path('aes.txt' if method == 'aes' else 'rsa.txt')
    return {'display': encoded, 'data': (encoded + '\n').encode('ascii'),
            'suggested_path': path, 'fingerprint': fingerprint}


def decrypt_text(text: str, fallback_method: str, *, password: Optional[str] = None,
                 private_key_pem: Optional[str] = None,
                 key_password: Optional[str] = None) -> dict:
    if not text.strip():
        raise CryptoError('Paste the encrypted text to decrypt.')
    try:
        encrypted = core.decode_container(text.encode('ascii'))
    except (UnicodeEncodeError, ValueError) as e:
        raise CryptoError(f'Invalid encrypted text: {e}')
    if encrypted.startswith(b'FSS2') and encrypted[6] == 1:
        raise CryptoError(
            'This Base64 contains an encrypted file. Use File → Decrypt to restore it.')
    method = core.detect_payload_format(encrypted) or fallback_method

    if method == 'aes':
        if not password:
            raise CryptoError('Password required.')
        try:
            plaintext, stored_hash = core.aes_decrypt_with_hash(encrypted, password)
        except ValueError:
            log_operation('DECRYPT_TEXT', '', 'AES-256', 'FAILED',
                           error='Wrong password or damaged data', additional='decrypt_text (gui)')
            raise CryptoError('Wrong password or damaged encrypted text.')
        fingerprint = None
    elif method == 'rsa':
        if not private_key_pem:
            raise CryptoError('Private key required.')
        try:
            plaintext, stored_hash = core.rsa_decrypt_hybrid_with_hash(
                encrypted, private_key_pem, key_password)
        except core.KeyFormatError as e:
            log_operation('DECRYPT_TEXT', '', 'RSA', 'FAILED',
                           error='Key problem: ' + str(e), additional='decrypt_text (gui)')
            raise CryptoError(str(e))
        except ValueError:
            log_operation('DECRYPT_TEXT', '', 'RSA', 'FAILED',
                           error='Wrong key or damaged data', additional='decrypt_text (gui)')
            raise CryptoError(
                'This private key does not match the key used to encrypt this text '
                '(or the text is damaged).')
        fingerprint = core.calculate_key_fingerprint(
            private_key_pem, is_public=False, key_password=key_password)
    else:
        raise CryptoError('Encryption method not recognized.')

    if not core.verify_hash_constant_time(stored_hash, hashlib.sha256(plaintext).hexdigest()):
        log_operation('DECRYPT_TEXT', '', method.upper(), 'FAILED',
                       error='Integrity check failed', additional='decrypt_text (gui)')
        raise CryptoError('Integrity check failed.')
    try:
        decoded = plaintext.decode('utf-8')
    except UnicodeDecodeError:
        raise CryptoError('The decrypted content is not valid UTF-8 text.')
    path = suggest_text_path()
    return {'display': decoded, 'data': plaintext, 'suggested_path': path,
            'fingerprint': fingerprint}


def load_encrypted_text_file(path: str) -> str:
    """Load and validate a .txt file containing an encrypted Base64 message."""
    if not path.lower().endswith('.txt'):
        raise CryptoError('Only .txt files containing encrypted Base64 text are accepted.')
    max_encoded_text = 4 * ((core.MAX_TEXT_SIZE + 4096 + 2) // 3)
    try:
        data = core.read_limited(path, max_encoded_text).decode('ascii')
        encrypted = core.decode_container(data.encode('ascii'))
    except (OSError, UnicodeDecodeError, ValueError) as e:
        raise CryptoError(f'This is not a valid encrypted Base64 text file: {e}')
    if encrypted.startswith(b'FSS2') and encrypted[6] == 1:
        raise CryptoError(
            'This Base64 contains an encrypted file. Use File → Decrypt to restore it.')
    return data


def generate_keypair(keyname: str, password: Optional[str] = None) -> dict:
    keyname = core.sanitize_filename(keyname)
    if not keyname:
        raise CryptoError('Invalid key name.')
    if password:
        valid, msg = core.validate_password_strength_key(password)
        if not valid:
            raise CryptoError(msg)

    core.ensure_private_directory(KEYS_DIR)
    private_pem, public_pem = core.generate_rsa_keypair(password)
    fingerprint = core.calculate_key_fingerprint(public_pem, is_public=True)
    created = datetime.datetime.now()

    base_name = core.get_key_base_name(keyname, fingerprint, secrets.token_hex(8))
    private_file = os.path.join(KEYS_DIR, core.get_key_filename(base_name, is_public=False))
    public_file = os.path.join(KEYS_DIR, core.get_key_filename(base_name, is_public=True))
    info_file = os.path.join(KEYS_DIR, core.get_key_info_filename(base_name))
    qr_file = os.path.join(KEYS_DIR, f'{base_name}_public_qr.png')
    qr_data = public_key_qr_png(public_pem)

    _write_atomic(private_file, private_pem.encode('utf-8'))
    _write_atomic(public_file, public_pem.encode('utf-8'))
    _write_atomic(qr_file, qr_data)
    info_text = (
        f"Key name:            {keyname}\n"
        f"Created:             {created.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Key size:            {core.RSA_KEY_SIZE} bit RSA\n"
        f"Password protected:  {'yes' if password else 'no'}\n"
        f"Private key file:    {os.path.basename(private_file)}\n"
        f"Public key file:     {os.path.basename(public_file)}\n"
        f"Public key QR file:  {os.path.basename(qr_file)}\n"
        f"Fingerprint SHA-256 (SPKI, full):\n"
        f"  {fingerprint}\n"
    )
    try:
        _write_atomic(info_file, info_text.encode('utf-8'))
    except Exception:
        info_file = None  # Non-fatal: the keys themselves are what matters.

    log_operation('KEYGEN', private_file, 'RSA4096', 'SUCCESS', keyname=keyname,
                   key_fingerprint=fingerprint,
                   additional=f'protected={bool(password)} (gui)')
    return {
        'keyname': keyname, 'private_file': private_file, 'public_file': public_file,
        'info_file': info_file, 'qr_file': qr_file, 'qr_data': qr_data,
        'fingerprint': fingerprint, 'protected': bool(password),
    }


class Worker(QObject):
    succeeded = Signal(dict)
    failed = Signal(str)

    def __init__(self, fn, kwargs):
        super().__init__()
        self._fn = fn
        self._kwargs = kwargs

    def run(self):
        try:
            result = self._fn(**self._kwargs)
        except CryptoError as e:
            self.failed.emit(str(e))
        except Exception as e:
            self.failed.emit(f'Unexpected error: {e}')
        else:
            self.succeeded.emit(result)


class PasswordField(QWidget):
    """A QLineEdit with a native show/hide toggle — copy/paste (Ctrl+C/V,
    right-click menu) work automatically, it's a built-in Qt control."""

    def __init__(self, placeholder: str = '', parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self.edit = QLineEdit()
        self.edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit.setPlaceholderText(placeholder)
        self.toggle = QToolButton()
        self.toggle.setText('Show')
        self.toggle.setCheckable(True)
        self.toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle.toggled.connect(self._on_toggle)
        self.clear_button = QToolButton()
        self.clear_button.setText('Clear')
        self.clear_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_button.clicked.connect(self._on_clear_clicked)
        layout.addWidget(self.edit, 1)
        layout.addWidget(self.toggle)
        layout.addWidget(self.clear_button)

    def _on_clear_clicked(self):
        self.clear()
        self.edit.setFocus()

    def _on_toggle(self, checked: bool):
        self.edit.setEchoMode(QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password)
        self.toggle.setText('Hide' if checked else 'Show')

    def text(self) -> str:
        return self.edit.text()

    def clear(self):
        self.edit.clear()
        self.toggle.setChecked(False)


class AesPasswordHint(QLabel):
    """Live AES password requirements and confirmation feedback."""

    def __init__(self, password_field: PasswordField,
                 confirm_field: Optional[PasswordField] = None, parent=None):
        super().__init__(parent)
        self.password_field = password_field
        self.confirm_field = confirm_field
        self.setObjectName('fieldNote')
        self.setWordWrap(True)
        self.refresh()

    def refresh(self) -> bool:
        password = self.password_field.text()
        valid, message = core.validate_password_strength(password)
        state = 'error'
        if not password:
            message = ('AES password: 12–128 characters, at least 5 different characters, '
                       'and a unique passphrase.')
            state = ''
        elif valid and self.confirm_field is not None:
            confirmation = self.confirm_field.text()
            if not confirmation:
                message = 'Password accepted. Repeat it to confirm.'
                state = ''
                valid = False
            elif password != confirmation:
                message = 'Passwords do not match.'
                valid = False
            elif core.estimate_password_weakness(password):
                message = ('Accepted, but this password looks weak (repetitive or '
                           'predictable) — consider changing it before you save.')
                state = 'weak'
            else:
                message = 'Password accepted and confirmed.'
                state = 'ok'
        elif valid:
            if core.estimate_password_weakness(password):
                message = ('Accepted, but this password looks weak (repetitive or '
                           'predictable) — consider changing it before you save.')
                state = 'weak'
            else:
                message = 'Password meets the AES requirements.'
                state = 'ok'
        self.setProperty('state', state)
        self.setText(message)
        self.style().unpolish(self)
        self.style().polish(self)
        return valid


class KeyPasswordHint(QLabel):
    """Live RSA private-key password requirements and confirmation feedback
    (mirrors AesPasswordHint, but against the stricter key-password rules)."""

    def __init__(self, password_field: PasswordField,
                 confirm_field: Optional[PasswordField] = None, parent=None):
        super().__init__(parent)
        self.password_field = password_field
        self.confirm_field = confirm_field
        self.setObjectName('fieldNote')
        self.setWordWrap(True)
        self.refresh()

    def refresh(self) -> bool:
        password = self.password_field.text()
        valid, message = core.validate_password_strength_key(password)
        state = 'error'
        if not password:
            message = ('Key password: 12+ characters with an uppercase letter, a '
                       'lowercase letter, a digit, and a special character (!@#$%^&*…).')
            state = ''
        elif valid and self.confirm_field is not None:
            confirmation = self.confirm_field.text()
            if not confirmation:
                message = 'Password accepted. Repeat it to confirm.'
                state = ''
                valid = False
            elif password != confirmation:
                message = 'Passwords do not match.'
                valid = False
            else:
                message = 'Password accepted and confirmed.'
                state = 'ok'
        elif valid:
            message = 'Password meets the key requirements.'
            state = 'ok'
        self.setProperty('state', state)
        self.setText(message)
        self.style().unpolish(self)
        self.style().polish(self)
        return valid


class DropZone(QFrame):
    """Accept a local file dropped from the operating-system file manager."""

    filesChosen = Signal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName('dropZone')
        self.setAcceptDrops(True)
        self.setMinimumHeight(110)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(10)

        self.icon_label = QLabel('+')
        self.icon_label.setObjectName('dropIcon')
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.hint_label = QLabel('Drop files here (up to 5)')
        self.hint_label.setObjectName('dropHint')
        self.hint_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.sub_label = QLabel('or')
        self.sub_label.setObjectName('dropSub')
        self.sub_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.browse_button = QPushButton('Browse files…')
        self.browse_button.setObjectName('browseButton')
        self.browse_button.setMinimumSize(160, 42)
        self.browse_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.browse_button.clicked.connect(self._browse)

        layout.addWidget(self.icon_label)
        layout.addWidget(self.hint_label)
        layout.addWidget(self.sub_label)
        layout.addWidget(self.browse_button, 0, Qt.AlignmentFlag.AlignCenter)

    def _browse(self):
        paths, _ = QFileDialog.getOpenFileNames(self, 'Choose files')
        if paths:
            self.filesChosen.emit(paths)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setProperty('dragActive', True)
            self.style().unpolish(self)
            self.style().polish(self)

    def dragLeaveEvent(self, event):
        self.setProperty('dragActive', False)
        self.style().unpolish(self)
        self.style().polish(self)

    def dropEvent(self, event: QDropEvent):
        self.setProperty('dragActive', False)
        self.style().unpolish(self)
        self.style().polish(self)
        urls = event.mimeData().urls()
        if not urls:
            return
        paths = [u.toLocalFile() for u in urls
                 if u.toLocalFile() and os.path.isfile(u.toLocalFile())]
        if paths:
            self.filesChosen.emit(paths)


class FileChip(QFrame):
    """The currently selected file — name, size, and a way to clear it."""

    cleared = Signal()

    def __init__(self, parent=None, badge: str = 'FILE'):
        super().__init__(parent)
        self.setObjectName('fileChip')
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 10, 10, 10)
        outer.setSpacing(4)
        layout = QHBoxLayout()
        outer.addLayout(layout)

        icon = QLabel(badge)
        icon.setObjectName('fileTypeBadge')
        self.name_label = QLabel('')
        self.name_label.setObjectName('fileChipName')
        # A long file name must never force the whole panel wider: it takes the
        # free space in the row and wraps (at _ . - or every few characters)
        # when there isn't enough, so the whole name stays readable.
        self.name_label.setWordWrap(True)
        self.name_label.setMinimumWidth(1)
        self.name_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.size_label = QLabel('')
        self.size_label.setObjectName('fileChipSize')

        remove = QToolButton()
        remove.setText('✕')
        remove.setObjectName('fileChipRemove')
        remove.setCursor(Qt.CursorShape.PointingHandCursor)
        remove.clicked.connect(self.cleared.emit)

        layout.addWidget(icon)
        layout.addWidget(self.name_label, 1)
        layout.addWidget(self.size_label)
        layout.addWidget(remove)

        # Per-file outcome shown under the row (only used for files that failed).
        self.result_label = QLabel('')
        self.result_label.setObjectName('fieldNote')
        self.result_label.setProperty('state', 'error')
        self.result_label.setWordWrap(True)
        self.result_label.setVisible(False)
        outer.addWidget(self.result_label)
        self.hide()

    def set_result(self, message: str):
        self.result_label.setText(message)
        self.result_label.setVisible(bool(message))

    def clear_result(self):
        self.set_result('')

    def set_file(self, path: str):
        name = os.path.basename(path)
        parts = re.split(r'(?<=[_.\-])', name)
        self.name_label.setText('\u200b'.join(
            _soft_wrap(part, 24) if len(part) > 24 else part for part in parts))
        try:
            self.size_label.setText(core.format_size(os.path.getsize(path)))
        except OSError:
            self.size_label.setText('')
        self.show()


class KeyPicker(QWidget):
    """Browse for a key file. A public key is validated and fingerprinted
    immediately on selection (no password needed for that). A private key
    only gets a quick "does this even look like a private key" check here
    — its fingerprint needs the password, so that's shown after decrypt
    actually succeeds."""

    changed = Signal()  # emitted once pem_text is settled (loaded, failed, or cleared)

    def __init__(self, browse_label: str, dialog_title: str, mode: str = 'public', parent=None):
        super().__init__(parent)
        self.mode = mode
        self._load_label = browse_label
        self._change_label = f'Change {mode} key…'
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        row = QHBoxLayout()
        row.setSpacing(6)
        self.path_edit = QLineEdit()
        self.path_edit.setReadOnly(True)
        self.path_edit.setPlaceholderText('No key selected')
        self.browse_button = QPushButton(browse_label)
        self.browse_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_button = QPushButton('Clear')
        self.clear_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_button.setEnabled(False)
        row.addWidget(self.path_edit, 1)
        row.addWidget(self.browse_button)
        row.addWidget(self.clear_button)
        layout.addLayout(row)

        self.fingerprint_label = QLabel('')
        self.fingerprint_label.setObjectName('fingerprint')
        self.fingerprint_label.setWordWrap(True)
        layout.addWidget(self.fingerprint_label)

        self._dialog_title = dialog_title
        self.browse_button.clicked.connect(self._browse)
        self.clear_button.clicked.connect(self.clear)
        self.pem_text: Optional[str] = None

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, self._dialog_title, KEYS_DIR,
            'PEM keys (*.pem *.txt);;All files (*)')
        if path:
            self.load(path)

    def load(self, path: str):
        self.path_edit.setText(path)
        self.clear_button.setEnabled(True)
        self.browse_button.setText(self._load_label)
        self.pem_text = None
        self.fingerprint_label.setText('')
        try:
            pem = core.read_limited(path, core.MAX_KEY_SIZE).decode('utf-8')
        except Exception as e:
            self.show_error(f'Could not read the file: {e}')
            self.changed.emit()
            return

        if self.mode == 'public':
            if not core.validate_rsa_key(pem, is_public=True):
                self.show_error('This is not a valid RSA-4096 public key.')
                self.changed.emit()
                return
            self.pem_text = pem
            self.show_fingerprint(core.calculate_key_fingerprint(pem, is_public=True))
        else:
            if not core.looks_like_private_key_pem(pem):
                self.show_error('This file does not look like a private key. '
                                 'Did you select the public key by mistake?')
                self.changed.emit()
                return
            self.pem_text = pem
            self.fingerprint_label.setProperty('state', 'ok')
            self.fingerprint_label.setText(
                'Private key loaded — enter its password if it has one.')
            self._restyle()
        self.browse_button.setText(self._change_label)
        self.changed.emit()

    def clear(self):
        self.path_edit.clear()
        self.clear_button.setEnabled(False)
        self.browse_button.setText(self._load_label)
        self.pem_text = None
        self.fingerprint_label.setText('')
        self.changed.emit()

    def show_fingerprint(self, fingerprint: str):
        self.fingerprint_label.setProperty('state', 'ok')
        self.fingerprint_label.setText(f'SHA-256 fingerprint: {fingerprint}')
        self._restyle()

    def show_error(self, message: str):
        self.fingerprint_label.setProperty('state', 'error')
        self.fingerprint_label.setText(message)
        self._restyle()

    def _restyle(self):
        self.fingerprint_label.style().unpolish(self.fingerprint_label)
        self.fingerprint_label.style().polish(self.fingerprint_label)


class StatusStrip(QFrame):
    """The result panel: success (path + copy/save-as + fingerprint) or a
    plain error message. Hidden until the first operation finishes."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName('statusStrip')
        self.setVisible(False)

        self.layout_ = QVBoxLayout(self)
        self.layout_.setContentsMargins(16, 14, 16, 14)
        self.layout_.setSpacing(8)

        title_row = QHBoxLayout()
        self.title_label = QLabel('')
        self.title_label.setObjectName('statusTitle')
        self.clear_button = QPushButton('Clear result')
        self.clear_button.setVisible(False)
        title_row.addWidget(self.title_label)
        title_row.addStretch(1)
        title_row.addWidget(self.clear_button)
        self.layout_.addLayout(title_row)

        self.detail_label = QLabel('')
        self.detail_label.setObjectName('statusDetail')
        self.detail_label.setWordWrap(True)
        self.layout_.addWidget(self.detail_label)

        path_row = QHBoxLayout()
        path_row.setSpacing(6)
        self.path_edit = QLineEdit()
        self.path_edit.setReadOnly(True)
        self.copy_button = QPushButton('Copy path')
        self.copy_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.save_as_button = QPushButton('Save a copy as…')
        self.save_as_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.open_folder_button = QPushButton('Open folder')
        self.open_folder_button.setCursor(Qt.CursorShape.PointingHandCursor)
        path_row.addWidget(self.path_edit, 1)
        path_row.addWidget(self.copy_button)
        path_row.addWidget(self.save_as_button)
        path_row.addWidget(self.open_folder_button)
        self.path_row_widget = QWidget()
        self.path_row_widget.setLayout(path_row)
        self.layout_.addWidget(self.path_row_widget)

        self.copy_button.clicked.connect(self._copy_path)
        self.open_folder_button.clicked.connect(self._open_folder)

    def _copy_path(self):
        QGuiApplication.clipboard().setText(self.path_edit.text())
        _flash_button_text(self.copy_button, 'Copied')

    def _open_folder(self):
        path = self.path_edit.text()
        if path:
            open_folder(os.path.dirname(path))

    def show_success(self, title: str, path: str, extra: str = ''):
        self.setProperty('state', 'success')
        self.title_label.setText(title)
        self.detail_label.setText(extra)
        self.detail_label.setVisible(bool(extra))
        self.path_edit.setText(path)
        self.path_row_widget.setVisible(True)
        self.copy_button.setText('Copy path')
        self.setVisible(True)
        self._restyle()

    def show_error(self, message: str):
        self.setProperty('state', 'error')
        self.title_label.setText('Operation failed')
        self.detail_label.setText(message)
        self.detail_label.setVisible(True)
        self.path_row_widget.setVisible(False)
        self.setVisible(True)
        self._restyle()

    def clear(self):
        self.title_label.clear()
        self.detail_label.clear()
        self.path_edit.clear()
        self.copy_button.setText('Copy path')
        self.setProperty('state', '')
        self.setVisible(False)
        self._restyle()

    def _restyle(self):
        self.style().unpolish(self)
        self.style().polish(self)


class FilePanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._paths_by_mode = {'encrypt': [], 'decrypt': []}
        self.selected_paths = self._paths_by_mode['encrypt']
        self._file_chips: dict = {}
        self._run_queue: list = []
        self._batch_results: list = []
        self._thread: Optional[QThread] = None
        self._worker: Optional[Worker] = None
        self._last_data: Optional[bytes] = None
        self._last_saved_path = ''
        self._base64_source_path = ''
        self._base64_target_path = ''
        self._file_started_at = 0.0

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 18, 24, 18)
        root.setSpacing(10)

        heading = QLabel('File')
        heading.setObjectName('panelHeading')
        subheading = QLabel(
            '<b>Encrypt or decrypt a file with AES-256-GCM or RSA-4096.</b> Process up to '
            '5 files at once, up to a combined 1 GiB total. Larger operations may also '
            'be limited by the memory available while processing. <b>Keep them for '
            'your own archive, or send them by email, chat, or app, even a public '
            'one.</b> Optionally export a Base64 copy too, handy for text-only fields. '
            '<b>Only whoever has the password (AES) or the private key plus its '
            'optional password (RSA) can decrypt them.</b>')
        subheading.setObjectName('panelSubheading')
        subheading.setWordWrap(True)
        heading_row = QHBoxLayout()
        heading_row.addWidget(heading)
        heading_row.addStretch(1)
        root.addLayout(heading_row)
        root.addWidget(subheading)

        self.credentials_warning = QLabel(
            '⚠ If you forget the password or lose the private key, the data cannot '
            'be recovered — there is no backdoor or master key.')
        self.credentials_warning.setObjectName('fieldNote')
        self.credentials_warning.setProperty('state', 'weak')
        self.credentials_warning.setWordWrap(True)
        root.addWidget(self.credentials_warning)
        self.credentials_warning.style().unpolish(self.credentials_warning)
        self.credentials_warning.style().polish(self.credentials_warning)

        files_note = QLabel(
            'Load up to 5 files — they’re processed together with the same password/key. '
            'Remove one with ✕, or “Clear all files” to start a new batch '
            '(password/key are kept). Results are saved automatically in the app’s '
            'files folder; your original files are never modified.')
        files_note.setObjectName('fieldNote')
        files_note.setWordWrap(True)
        root.addWidget(files_note)

        mode_row = QHBoxLayout()
        mode_row.setSpacing(0)
        self.encrypt_toggle = QPushButton('Encrypt')
        self.decrypt_toggle = QPushButton('Decrypt')
        for b in (self.encrypt_toggle, self.decrypt_toggle):
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
        self.encrypt_toggle.setObjectName('modeLeft')
        self.decrypt_toggle.setObjectName('modeRight')
        self.encrypt_toggle.setChecked(True)
        self.mode_group = QButtonGroup(self)
        self.mode_group.setExclusive(True)
        self.mode_group.addButton(self.encrypt_toggle)
        self.mode_group.addButton(self.decrypt_toggle)
        self.mode_group.buttonToggled.connect(self._on_mode_changed)
        mode_row.addWidget(self.encrypt_toggle)
        mode_row.addWidget(self.decrypt_toggle)
        mode_wrap = QWidget()
        mode_wrap.setObjectName('modeToggle')
        mode_wrap.setLayout(mode_row)
        root.addWidget(mode_wrap, 0, Qt.AlignmentFlag.AlignLeft)

        self.dropzone = DropZone()
        self.dropzone.filesChosen.connect(self._add_files)
        root.addWidget(self.dropzone)

        self.files_list_layout = QVBoxLayout()
        self.files_list_layout.setSpacing(6)
        files_list_widget = QWidget()
        files_list_widget.setLayout(self.files_list_layout)
        root.addWidget(files_list_widget)

        files_actions_row = QHBoxLayout()
        self.files_count_label = QLabel('')
        self.files_count_label.setObjectName('fieldNote')
        files_actions_row.addWidget(self.files_count_label)
        self.files_not_loaded_label = QLabel('')
        self.files_not_loaded_label.setObjectName('fieldNote')
        self.files_not_loaded_label.setProperty('state', 'error')
        self.files_not_loaded_label.setContentsMargins(10, 0, 0, 0)
        self.files_not_loaded_label.setWordWrap(True)
        files_actions_row.addWidget(self.files_not_loaded_label, 1)
        self.clear_all_files_button = QPushButton('Clear all files')
        self.clear_all_files_button.clicked.connect(self._clear_all_files)
        self.clear_all_files_button.setVisible(False)
        files_actions_row.addWidget(self.clear_all_files_button)
        root.addLayout(files_actions_row)

        method_label = QLabel('Method')
        method_label.setObjectName('fieldLabel')
        root.addWidget(method_label)
        self.method_combo = QComboBox()
        self.method_combo.addItem('Password (AES-256-GCM)', 'aes')
        self.method_combo.addItem('RSA-4096 key', 'rsa')
        self.method_combo.currentIndexChanged.connect(self._on_method_changed)
        root.addWidget(self.method_combo)

        self.fields_stack = QStackedWidget()
        root.addWidget(self.fields_stack)

        self.aes_encrypt_page = self._build_aes_encrypt_page()
        self.aes_decrypt_page = self._build_aes_decrypt_page()
        self.rsa_encrypt_page = self._build_rsa_encrypt_page()
        self.rsa_decrypt_page = self._build_rsa_decrypt_page()
        for page in (self.aes_encrypt_page, self.aes_decrypt_page,
                     self.rsa_encrypt_page, self.rsa_decrypt_page):
            self.fields_stack.addWidget(page)

        self.action_button = QPushButton('Encrypt file')
        self.action_button.setObjectName('primaryButton')
        self.action_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.action_button.setEnabled(False)
        self.action_button.clicked.connect(self._run)
        root.addWidget(self.action_button)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)  # indeterminate
        self.progress.setVisible(False)
        self.progress.setTextVisible(False)
        root.addWidget(self.progress)

        self.status = StatusStrip()
        # Results are saved automatically in FILES_DIR; "Open folder" is enough.
        self.status.save_as_button.setVisible(False)
        self.status.clear_button.setVisible(True)
        self.status.clear_button.clicked.connect(self._clear_result)
        base64_row = QHBoxLayout()
        self.base64_note = QLabel(
            'Optional: export Base64 mainly for email, chat, or text-only fields.')
        self.base64_note.setObjectName('fieldNote')
        self.base64_note.setWordWrap(True)
        self.export_base64_button = QPushButton('Export Base64 copy')
        self.export_base64_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.export_base64_button.clicked.connect(self._export_base64)
        base64_row.addWidget(self.base64_note, 1)
        base64_row.addWidget(self.export_base64_button)
        self.base64_row_widget = QWidget()
        self.base64_row_widget.setLayout(base64_row)
        self.base64_row_widget.setVisible(False)
        self.status.layout_.addWidget(self.base64_row_widget)
        root.addWidget(self.status)

        end_session_row = QHBoxLayout()
        end_session_row.addStretch(1)
        self.end_session_button = QPushButton('End session')
        self.end_session_button.clicked.connect(self._end_session)
        end_session_row.addWidget(self.end_session_button)
        root.addLayout(end_session_row)
        end_session_note = QLabel(
            'Clears everything on this panel: loaded files, results, password/key. '
            'Files already saved to disk are not deleted.')
        end_session_note.setObjectName('fieldNote')
        end_session_note.setWordWrap(True)
        end_session_note.setAlignment(Qt.AlignmentFlag.AlignRight)
        root.addWidget(end_session_note)

        root.addStretch(1)

        self._sync_fields_page()
        self._wire_validation()

    def _build_aes_encrypt_page(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        pw_label = QLabel('Password')
        pw_label.setObjectName('fieldLabel')
        layout.addWidget(pw_label)
        self.aes_enc_password = PasswordField('Encryption password')
        layout.addWidget(self.aes_enc_password)
        confirm_label = QLabel('Confirm password')
        confirm_label.setObjectName('fieldLabel')
        layout.addWidget(confirm_label)
        self.aes_enc_confirm = PasswordField('Repeat the password')
        layout.addWidget(self.aes_enc_confirm)
        self.aes_password_hint = AesPasswordHint(
            self.aes_enc_password, self.aes_enc_confirm)
        layout.addWidget(self.aes_password_hint)
        return w

    def _build_aes_decrypt_page(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        pw_label = QLabel('Password')
        pw_label.setObjectName('fieldLabel')
        layout.addWidget(pw_label)
        self.aes_dec_password = PasswordField('Password used for encryption')
        layout.addWidget(self.aes_dec_password)
        return w

    def _build_rsa_encrypt_page(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        note = QLabel('Hybrid encryption: a random AES-256 key encrypts the file, then the '
                      'RSA-4096 public key encrypts that key.')
        note.setObjectName('fieldNote')
        note.setWordWrap(True)
        layout.addWidget(note)
        label = QLabel("Recipient's public key")
        label.setObjectName('fieldLabel')
        layout.addWidget(label)
        self.rsa_enc_key = KeyPicker('Load public key…', 'Choose the public key', mode='public')
        layout.addWidget(self.rsa_enc_key)
        return w

    def _build_rsa_decrypt_page(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        label = QLabel('Your private key')
        label.setObjectName('fieldLabel')
        layout.addWidget(label)
        self.rsa_dec_key = KeyPicker('Load private key…', 'Choose the private key', mode='private')
        layout.addWidget(self.rsa_dec_key)
        pw_label = QLabel('Key password (leave blank if unprotected)')
        pw_label.setObjectName('fieldLabel')
        layout.addWidget(pw_label)
        self.rsa_dec_password = PasswordField('Private key password (optional)')
        layout.addWidget(self.rsa_dec_password)
        return w

    def _wire_validation(self):
        self.aes_enc_password.edit.textChanged.connect(self._validate)
        self.aes_enc_confirm.edit.textChanged.connect(self._validate)
        self.aes_dec_password.edit.textChanged.connect(self._validate)
        self.rsa_dec_password.edit.textChanged.connect(self._validate)
        self.rsa_enc_key.changed.connect(self._validate)
        self.rsa_dec_key.changed.connect(self._validate)
        # Removing the private key also wipes the password typed for it.
        self.rsa_dec_key.clear_button.clicked.connect(self.rsa_dec_password.clear)

    def _on_mode_changed(self, *_):
        self._switch_mode_files()
        self._sync_fields_page()
        self._validate()

    def _switch_mode_files(self):
        self.selected_paths = self._paths_by_mode[self._current_mode()]
        for chip in self._file_chips.values():
            self.files_list_layout.removeWidget(chip)
            chip.deleteLater()
        self._file_chips = {}
        for path in self.selected_paths:
            chip = FileChip()
            chip.set_file(path)
            chip.cleared.connect(lambda p=path: self._remove_file(p))
            self.files_list_layout.addWidget(chip)
            self._file_chips[path] = chip
        self._update_files_count()
        self.status.setVisible(False)

    def _on_method_changed(self, *_):
        self._sync_fields_page()
        self._validate()

    def _current_mode(self) -> str:
        return 'encrypt' if self.encrypt_toggle.isChecked() else 'decrypt'

    def _current_method(self) -> str:
        return self.method_combo.currentData()

    def _sync_fields_page(self):
        mode, method = self._current_mode(), self._current_method()
        if method == 'aes' and mode == 'encrypt':
            self.fields_stack.setCurrentWidget(self.aes_encrypt_page)
        elif method == 'aes' and mode == 'decrypt':
            self.fields_stack.setCurrentWidget(self.aes_decrypt_page)
        elif method == 'rsa' and mode == 'encrypt':
            self.fields_stack.setCurrentWidget(self.rsa_encrypt_page)
        else:
            self.fields_stack.setCurrentWidget(self.rsa_decrypt_page)
        self._update_action_button_text()
        self.status.setVisible(False)

    def _file_size(self, path: str) -> int:
        try:
            return os.path.getsize(path)
        except OSError:
            return 0

    def _add_files(self, paths: list):
        added = 0
        skipped_cap = 0
        skipped_size = 0
        total_bytes = sum(self._file_size(p) for p in self.selected_paths)
        for raw in paths:
            path = os.path.abspath(raw)
            if path in self.selected_paths:
                continue
            if len(self.selected_paths) >= 5:
                skipped_cap += 1
                continue
            file_size = self._file_size(path)
            if total_bytes + file_size > core.MAX_FILE_SIZE:
                skipped_size += 1
                continue
            self.selected_paths.append(path)
            chip = FileChip()
            chip.set_file(path)
            chip.cleared.connect(lambda p=path: self._remove_file(p))
            self.files_list_layout.addWidget(chip)
            self._file_chips[path] = chip
            total_bytes += file_size
            added += 1
        self._update_files_count(skipped_cap + skipped_size, size_limit=skipped_size > 0)
        if added:
            self.status.setVisible(False)
        self._validate()

    def _remove_file(self, path: str):
        if path in self.selected_paths:
            self.selected_paths.remove(path)
        chip = self._file_chips.pop(path, None)
        if chip is not None:
            self.files_list_layout.removeWidget(chip)
            chip.deleteLater()
        self._update_files_count()
        self.status.setVisible(False)
        self._validate()

    def _clear_all_files(self):
        for chip in self._file_chips.values():
            self.files_list_layout.removeWidget(chip)
            chip.deleteLater()
        self._file_chips.clear()
        self.selected_paths.clear()
        self._update_files_count()
        self.status.clear()
        self.base64_row_widget.setVisible(False)
        self._last_data = None
        self._validate()

    def _update_files_count(self, not_loaded: int = 0, size_limit: bool = False):
        """Refresh the loaded / not-loaded counters. `not_loaded` is only
        non-zero right after a drop or selection that had files rejected;
        every other change (remove, clear, mode switch) resets it."""
        n = len(self.selected_paths)
        if n:
            self.files_count_label.setText(f'{n} file loaded' if n == 1 else f'{n} files loaded')
        else:
            self.files_count_label.setText('No files loaded' if not_loaded else '')
        text = (f'{not_loaded} file not loaded' if not_loaded == 1
                else f'{not_loaded} files not loaded' if not_loaded else '')
        if text and size_limit:
            text += (f': combined size limit '
                     f'({core.format_size(core.MAX_FILE_SIZE)}) exceeded')
        self.files_not_loaded_label.setText(text)
        self.files_not_loaded_label.style().unpolish(self.files_not_loaded_label)
        self.files_not_loaded_label.style().polish(self.files_not_loaded_label)
        self.clear_all_files_button.setVisible(n > 0)

    def _update_action_button_text(self):
        mode = self._current_mode()
        n = len(self.selected_paths)
        verb = 'Encrypt' if mode == 'encrypt' else 'Decrypt'
        noun = 'files' if n != 1 else 'file'
        self.action_button.setText(f'{verb} {noun}')

    def _validate(self):
        mode, method = self._current_mode(), self._current_method()
        ok = bool(self.selected_paths)
        if method == 'aes' and mode == 'encrypt':
            password_ok = self.aes_password_hint.refresh()
            ok = ok and password_ok
        elif ok and method == 'aes' and mode == 'decrypt':
            ok = bool(self.aes_dec_password.text())
        self._update_action_button_text()
        self.action_button.setEnabled(ok and self._thread is None)

    def _run(self):
        mode, method = self._current_mode(), self._current_method()
        if not self.selected_paths:
            return
        if method == 'rsa' and mode == 'encrypt' and not self.rsa_enc_key.pem_text:
            self.status.show_error('RSA encryption requires a loaded public key.')
            return
        if method == 'rsa' and mode == 'decrypt' and not self.rsa_dec_key.pem_text:
            self.status.show_error('RSA decryption requires a loaded private key.')
            return

        self.status.setVisible(False)
        self.base64_row_widget.setVisible(False)
        self.progress.setVisible(True)
        self.action_button.setEnabled(False)
        for chip in self._file_chips.values():
            chip.clear_result()
        self._run_queue = list(self.selected_paths)
        self._batch_total = len(self._run_queue)
        self._batch_results = []
        self._run_next_file()

    def _current_run_kwargs(self, filepath: str):
        mode, method = self._current_mode(), self._current_method()
        if mode == 'encrypt' and method == 'aes':
            return encrypt_file, dict(filepath=filepath, method='aes',
                                       password=self.aes_enc_password.text())
        if mode == 'encrypt' and method == 'rsa':
            return encrypt_file, dict(filepath=filepath, method='rsa',
                                       public_key_pem=self.rsa_enc_key.pem_text)
        if mode == 'decrypt' and method == 'aes':
            return decrypt_file, dict(filepath=filepath, fallback_method='aes',
                                       password=self.aes_dec_password.text())
        return decrypt_file, dict(filepath=filepath, fallback_method='rsa',
                                   private_key_pem=self.rsa_dec_key.pem_text,
                                   key_password=self.rsa_dec_password.text() or None)

    def _run_next_file(self):
        if not self._run_queue:
            self._finish_batch()
            return
        filepath = self._run_queue.pop(0)
        fn, kwargs = self._current_run_kwargs(filepath)
        self._file_started_at = time.monotonic()

        self._thread = QThread(self)
        self._worker = Worker(fn, kwargs)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.succeeded.connect(lambda result, p=filepath: self._on_file_success(p, result))
        self._worker.failed.connect(lambda message, p=filepath: self._on_file_failure(p, message))
        self._worker.succeeded.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(self._on_file_thread_done)
        self._thread.start()

    def _on_file_thread_done(self):
        self._thread = None
        self._worker = None
        self._run_next_file()

    def _cleanup_thread(self):
        self._thread = None
        self._worker = None
        self.progress.setVisible(False)
        self._validate()

    def _on_file_success(self, filepath: str, result: dict):
        data = result['data']
        suggested = result['suggested_path']
        fingerprint = result.get('fingerprint')
        audit = result.get('audit') or {}
        try:
            _write_atomic(suggested, data)
        except Exception as e:
            if audit:
                log_operation(audit['operation'], suggested, audit['method'], 'FAILED',
                              error='Output write failed',
                              additional=audit.get('additional', ''),
                              key_fingerprint=audit.get('key_fingerprint', ''))
            self._batch_results.append({
                'filename': os.path.basename(filepath), 'path': filepath, 'ok': False,
                'detail': f'Succeeded but saving failed: {e}',
            })
            return
        if audit:
            log_operation(audit['operation'], suggested, audit['method'], 'SUCCESS',
                          file_hash=audit.get('file_hash', ''),
                          additional=audit.get('additional', ''),
                          key_fingerprint=audit.get('key_fingerprint', ''))
        self._last_data = data
        self._last_saved_path = suggested
        self._base64_source_path = suggested if result.get('base64_path') else ''
        self._base64_target_path = result.get('base64_path') or ''
        mode = self._current_mode()
        if mode == 'encrypt' and self._current_method() == 'rsa':
            self.rsa_enc_key.show_fingerprint(fingerprint)
        elif mode == 'decrypt' and self._current_method() == 'rsa':
            self.rsa_dec_key.show_fingerprint(fingerprint)
        elapsed = max(0.0, time.monotonic() - self._file_started_at)
        detail_bits = []
        if fingerprint:
            detail_bits.append(f'Key SHA-256 fingerprint: {fingerprint}')
        try:
            source_size = os.path.getsize(filepath)
            detail_bits.append(
                f'Original: {core.format_size(source_size)} · Result: {core.format_size(len(data))} '
                f'· Time: {elapsed:.2f} s')
        except OSError:
            pass
        self._batch_results.append({
            'filename': os.path.basename(filepath), 'path': filepath, 'ok': True,
            'saved_to': suggested, 'detail': ' · '.join(detail_bits),
        })

    def _on_file_failure(self, filepath: str, message: str):
        self._batch_results.append({
            'filename': os.path.basename(filepath), 'path': filepath, 'ok': False,
            'detail': message,
        })
        method = self._current_method()
        # With several files the error may only concern some of them, so it is
        # reported per file (and in the summary) instead of under the key field.
        if method == 'rsa' and self._batch_total == 1:
            picker = self.rsa_enc_key if self._current_mode() == 'encrypt' else self.rsa_dec_key
            if 'key' in message.lower():
                picker.show_error(message)

    def _finish_batch(self):
        self.progress.setVisible(False)
        results = self._batch_results
        total = len(results)
        ok_count = sum(1 for r in results if r['ok'])
        mode = self._current_mode()
        verb = 'encrypted' if mode == 'encrypt' else 'decrypted'

        if total == 1:
            r = results[0]
            if r['ok']:
                title = 'File encrypted' if mode == 'encrypt' else 'File decrypted'
                self.status.show_success(title, r.get('saved_to', ''), r.get('detail', ''))
                self.base64_row_widget.setVisible(bool(self._base64_target_path))
                self.export_base64_button.setEnabled(bool(self._base64_target_path))
                self.export_base64_button.setText('Export Base64 copy')
            else:
                self.status.show_error(r['detail'])
        else:
            lines = [f"{'✓' if r['ok'] else '✗'} {r['filename']}"
                     + (f" — {r['detail']}" if r['detail'] else '') for r in results]
            detail_text = '\n'.join(lines)
            if ok_count:
                title = (f'{total} files {verb}' if ok_count == total else
                         f'{ok_count} of {total} files {verb}, {total - ok_count} failed')
                # A trailing separator makes Open folder target FILES_DIR itself.
                self.status.show_success(title, os.path.join(FILES_DIR, ''), detail_text)
                if ok_count != total:
                    self.status.setProperty('state', 'error')
                    self.status._restyle()
            else:
                self.status.show_error(f'All {total} operations failed\n\n{detail_text}')

        # Files that were processed successfully leave the list (their results
        # are saved and summarised above); files that failed stay loaded so the
        # user can retry them. The AES password / RSA key are deliberately kept
        # loaded until "End session", so more files can reuse them.
        for r in results:
            if r['ok']:
                self._drop_file_from_list(r.get('path', ''))
            else:
                chip = self._file_chips.get(r.get('path', ''))
                if chip is not None:
                    chip.set_result('✗ ' + r['detail'])
        self._update_files_count()
        self._validate()

    def _drop_file_from_list(self, path: str):
        """Remove a file from the loaded list without touching the result view."""
        if path in self.selected_paths:
            self.selected_paths.remove(path)
        chip = self._file_chips.pop(path, None)
        if chip is not None:
            self.files_list_layout.removeWidget(chip)
            chip.deleteLater()

    def _clear_result(self):
        # Reset only the result/status view. The loaded files and any
        # password/key are left untouched.
        self.status.clear()
        self.base64_row_widget.setVisible(False)
        self._last_data = None

    def _end_session(self):
        # Full reset: both Encrypt's and Decrypt's file lists, the result
        # view, and every password/key field. Files already saved to disk
        # are never touched — this only clears what's on screen.
        self._paths_by_mode['encrypt'].clear()
        self._paths_by_mode['decrypt'].clear()
        for chip in self._file_chips.values():
            self.files_list_layout.removeWidget(chip)
            chip.deleteLater()
        self._file_chips = {}
        self._update_files_count()
        self.status.clear()
        self.base64_row_widget.setVisible(False)
        self._last_data = None
        self._last_saved_path = ''
        self.aes_enc_password.clear()
        self.aes_enc_confirm.clear()
        self.aes_dec_password.clear()
        self.rsa_dec_password.clear()
        self.rsa_enc_key.clear()
        self.rsa_dec_key.clear()
        self._validate()

    def _export_base64(self):
        if (self._thread is not None or not self._base64_source_path
                or not self._base64_target_path):
            return
        output_path, _ = QFileDialog.getSaveFileName(
            self, 'Save Base64 copy as', self._base64_target_path,
            'Base64 encrypted file (*.b64);;All files (*)')
        if not output_path:
            return
        self.export_base64_button.setEnabled(False)
        self.export_base64_button.setText('Exporting…')
        self.progress.setVisible(True)
        self.action_button.setEnabled(False)
        self._thread = QThread(self)
        self._worker = Worker(export_base64_copy, {
            'source_path': self._base64_source_path,
            'output_path': output_path,
        })
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.succeeded.connect(self._on_base64_success)
        self._worker.failed.connect(self._on_base64_failure)
        self._worker.succeeded.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(self._cleanup_thread)
        self._thread.start()

    def _on_base64_success(self, result: dict):
        path = result['path']
        current = self.status.detail_label.text().strip()
        message = f'Base64 copy: {path}'
        self.status.detail_label.setText(f'{current}\n{message}'.strip())
        self.status.detail_label.setVisible(True)
        self.export_base64_button.setText('Base64 exported')
        self.export_base64_button.setEnabled(False)
        log_operation('EXPORT_BASE64', path, 'BASE64', 'SUCCESS',
                      additional='export_base64_copy (gui)')

    def _on_base64_failure(self, message: str):
        current = self.status.detail_label.text().strip()
        error = f'Base64 export failed: {message}'
        self.status.detail_label.setText(f'{current}\n{error}'.strip())
        self.status.detail_label.setVisible(True)
        self.export_base64_button.setText('Retry Base64 export')
        self.export_base64_button.setEnabled(True)


class ChatTextPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._thread: Optional[QThread] = None
        self._worker: Optional[Worker] = None
        self._last_data: Optional[bytes] = None
        self._last_suggested_name: Optional[str] = None
        self._running_mode = 'encrypt'
        self._running_method = 'aes'
        self._running_input = ''
        self.transcript = []
        self._session_identity: Optional[str] = None
        self._sensitive_clipboard_value: Optional[str] = None
        self._clipboard_timer = QTimer(self)
        self._clipboard_timer.setSingleShot(True)
        self._clipboard_timer.timeout.connect(self._clear_sensitive_clipboard)
        app = QApplication.instance()
        if app is not None:
            app.aboutToQuit.connect(self._clear_sensitive_clipboard)

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 14, 18, 14)
        root.setSpacing(8)

        heading = QLabel('Text chat')
        heading.setObjectName('panelHeading')
        root.addWidget(heading)

        subtitle = QLabel(
            '<b>Encrypt a message here, then copy the result into any chat, email, or app '
            '— even a public one. With a password (AES), only whoever knows that '
            'password can decrypt it. With RSA keys, you encrypt with the recipient’s '
            'public key to send, and decrypt with your own private key to read what they '
            'send you.</b>')
        subtitle.setObjectName('panelSubheading')
        subtitle.setWordWrap(True)
        root.addWidget(subtitle)

        self.credentials_warning = QLabel(
            '⚠ If you forget the password or lose the private key, the data cannot '
            'be recovered — there is no backdoor or master key.')
        self.credentials_warning.setObjectName('fieldNote')
        self.credentials_warning.setProperty('state', 'weak')
        self.credentials_warning.setWordWrap(True)
        root.addWidget(self.credentials_warning)
        self.credentials_warning.style().unpolish(self.credentials_warning)
        self.credentials_warning.style().polish(self.credentials_warning)

        self.autosave_note = QLabel(
            'Messages and results remain in memory and are not saved automatically. '
            'Use “Save text…” to save the result currently displayed; the save dialog '
            'starts in the app’s texts folder, and you can choose another folder. '
            'The saved file is a complete record of the operation: it contains both '
            'the starting text and the result, with labels and a timestamp. Because it '
            'also holds readable text, not only Base64, it cannot be loaded back with '
            '“Load encrypted Base64…”, which requires a file containing only the '
            'Base64 text.')
        self.autosave_note.setObjectName('fieldNote')
        self.autosave_note.setWordWrap(True)
        root.addWidget(self.autosave_note)

        method_row = QHBoxLayout()
        method_label = QLabel('Method')
        method_label.setObjectName('fieldLabel')
        self.method_combo = QComboBox()
        self.method_combo.addItem('Password (AES-256-GCM)', 'aes')
        self.method_combo.addItem('RSA-4096 keys', 'rsa')
        method_row.addWidget(method_label)
        method_row.addWidget(self.method_combo, 1)
        root.addLayout(method_row)

        self.key_stack = QStackedWidget()
        self.aes_page = self._build_aes_page()
        self.rsa_page = self._build_rsa_page()
        self.key_stack.addWidget(self.aes_page)
        self.key_stack.addWidget(self.rsa_page)
        root.addWidget(self.key_stack)

        input_label = QLabel('Message or encrypted Base64 text')
        input_label.setObjectName('fieldLabel')
        root.addWidget(input_label)

        input_buttons = QHBoxLayout()
        input_buttons.addStretch(1)
        paste_button = QPushButton('Paste')
        paste_button.clicked.connect(self._paste_input)
        input_buttons.addWidget(paste_button)
        load_button = QPushButton('Load encrypted Base64…')
        load_button.clicked.connect(self._load_from_file)
        input_buttons.addWidget(load_button)
        clear_button = QPushButton('Clear')
        clear_button.clicked.connect(self._clear_input)
        input_buttons.addWidget(clear_button)
        root.addLayout(input_buttons)

        self.input_edit = QPlainTextEdit()
        self.input_edit.setPlaceholderText(
            'Write a message to encrypt, or paste encrypted Base64 text…')
        self.input_edit.setMinimumHeight(85)
        root.addWidget(self.input_edit)

        actions = QHBoxLayout()
        self.encrypt_button = QPushButton('Encrypt for sending')
        self.decrypt_button = QPushButton('Decrypt received text')
        for button in (self.encrypt_button, self.decrypt_button):
            button.setObjectName('primaryButton')
            button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.encrypt_button.clicked.connect(lambda: self._run('encrypt'))
        self.decrypt_button.clicked.connect(lambda: self._run('decrypt'))
        actions.addWidget(self.encrypt_button)
        actions.addWidget(self.decrypt_button)
        root.addLayout(actions)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.setVisible(False)
        root.addWidget(self.progress)

        result_row = QHBoxLayout()
        self.result_label = QLabel('Result')
        self.result_label.setObjectName('fieldLabel')
        result_row.addWidget(self.result_label)
        result_row.addStretch(1)
        self.copy_result = QPushButton('Copy result')
        self.copy_result.clicked.connect(self._copy_result)
        clear_result_button = QPushButton('Clear')
        clear_result_button.clicked.connect(self._clear_result)
        result_row.addWidget(self.copy_result)
        result_row.addWidget(clear_result_button)
        root.addLayout(result_row)
        clear_result_note = QLabel(
            'Clear removes only the result shown; nothing is deleted from disk.')
        clear_result_note.setObjectName('fieldNote')
        clear_result_note.setWordWrap(True)
        clear_result_note.setAlignment(Qt.AlignmentFlag.AlignRight)
        root.addWidget(clear_result_note)

        self.result_edit = QPlainTextEdit()
        self.result_edit.setReadOnly(True)
        self.result_edit.setMinimumHeight(80)
        root.addWidget(self.result_edit)

        self.status = StatusStrip()
        self.status.save_as_button.clicked.connect(self._save_as)
        self.status.save_as_button.setText('Save text…')
        root.addWidget(self.status)

        end_session_row = QHBoxLayout()
        end_session_row.addStretch(1)
        self.end_session_button = QPushButton('End session')
        self.end_session_button.clicked.connect(self._end_session)
        end_session_row.addWidget(self.end_session_button)
        root.addLayout(end_session_row)
        end_session_note = QLabel(
            'Clears history, input, result and password/key fields. '
            'Files you saved are not deleted.')
        end_session_note.setObjectName('fieldNote')
        end_session_note.setWordWrap(True)
        end_session_note.setAlignment(Qt.AlignmentFlag.AlignRight)
        root.addWidget(end_session_note)

        self.method_combo.currentIndexChanged.connect(self._sync_method)
        self.input_edit.textChanged.connect(self._on_input_changed)
        self.chat_password.edit.textChanged.connect(self._validate)
        self.public_key.changed.connect(self._validate)
        self.private_key.changed.connect(self._validate)
        # Removing the private key also wipes the password typed for it.
        self.private_key.clear_button.clicked.connect(self.private_password.clear)
        self.private_password.edit.textChanged.connect(self._validate)
        self._sync_method()

    def _build_aes_page(self) -> QWidget:
        page = QFrame()
        page.setObjectName('card')
        layout = QVBoxLayout(page)
        note = QLabel('The same shared password is used for sending and receiving.')
        note.setObjectName('fieldNote')
        note.setWordWrap(True)
        layout.addWidget(note)
        self.chat_password = PasswordField('Shared chat password')
        layout.addWidget(self.chat_password)
        self.aes_password_hint = AesPasswordHint(self.chat_password)
        layout.addWidget(self.aes_password_hint)
        return page

    def _build_rsa_page(self) -> QWidget:
        page = QFrame()
        page.setObjectName('card')
        layout = QVBoxLayout(page)
        layout.setSpacing(8)

        send_label = QLabel('SEND — recipient’s public key')
        send_label.setObjectName('fieldLabel')
        layout.addWidget(send_label)
        self.public_key = KeyPicker(
            'Load public key…', 'Choose the recipient’s public key', mode='public')
        layout.addWidget(self.public_key)

        receive_label = QLabel('RECEIVE — your private key')
        receive_label.setObjectName('fieldLabel')
        layout.addWidget(receive_label)
        self.private_key = KeyPicker(
            'Load private key…', 'Choose your private key', mode='private')
        layout.addWidget(self.private_key)
        pw_label = QLabel('Key password (leave blank if unprotected)')
        pw_label.setObjectName('fieldLabel')
        layout.addWidget(pw_label)
        self.private_password = PasswordField('Private key password (optional)')
        layout.addWidget(self.private_password)
        return page

    def _method(self) -> str:
        return self.method_combo.currentData()

    def _sync_method(self, *_):
        self.key_stack.setCurrentWidget(self.aes_page if self._method() == 'aes' else self.rsa_page)
        self.status.setVisible(False)
        self._validate()

    def _validate(self):
        has_input = bool(self.input_edit.toPlainText().strip())
        if self._method() == 'aes':
            has_password = bool(self.chat_password.text())
            password_ok = self.aes_password_hint.refresh()
            can_encrypt = has_input and password_ok
            can_decrypt = has_input and has_password
        else:
            can_encrypt = can_decrypt = has_input
        idle = self._thread is None
        self.encrypt_button.setEnabled(can_encrypt and idle)
        self.decrypt_button.setEnabled(can_decrypt and idle)

    def _on_input_changed(self):
        value = self.input_edit.toPlainText().strip()
        if len(value) >= core.MIN_ENCRYPTED_SIZE:
            try:
                container = core.decode_container(value.encode('ascii'))
                detected = core.detect_payload_format(container)
            except (UnicodeEncodeError, ValueError):
                detected = None
            if detected in ('aes', 'rsa'):
                index = self.method_combo.findData(detected)
                if index >= 0:
                    self.method_combo.setCurrentIndex(index)
        self._validate()

    def _run(self, mode: str):
        self._running_mode = mode
        self._running_method = self._method()
        self._running_input = self.input_edit.toPlainText()
        if self._running_method == 'rsa' and mode == 'encrypt' and not self.public_key.pem_text:
            self.status.show_error('RSA encryption requires a loaded public key.')
            return
        if self._running_method == 'rsa' and mode == 'decrypt' and not self.private_key.pem_text:
            self.status.show_error('RSA decryption requires a loaded private key.')
            return
        if mode == 'encrypt' and self._running_method == 'aes':
            fn = encrypt_text
            kwargs = {'text': self._running_input, 'method': 'aes',
                      'password': self.chat_password.text()}
        elif mode == 'encrypt':
            fn = encrypt_text
            kwargs = {'text': self._running_input, 'method': 'rsa',
                      'public_key_pem': self.public_key.pem_text}
        elif self._running_method == 'aes':
            fn = decrypt_text
            kwargs = {'text': self._running_input, 'fallback_method': 'aes',
                      'password': self.chat_password.text()}
        else:
            fn = decrypt_text
            kwargs = {'text': self._running_input, 'fallback_method': 'rsa',
                      'private_key_pem': self.private_key.pem_text,
                      'key_password': self.private_password.text() or None}

        self.status.setVisible(False)
        self.progress.setVisible(True)
        self.encrypt_button.setEnabled(False)
        self.decrypt_button.setEnabled(False)
        self._thread = QThread(self)
        self._worker = Worker(fn, kwargs)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.succeeded.connect(self._on_success)
        self._worker.failed.connect(self._on_failure)
        self._worker.succeeded.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(self._cleanup)
        self._thread.start()

    def _cleanup(self):
        self._thread = None
        self._worker = None
        self.progress.setVisible(False)
        self._validate()

    def _on_success(self, result: dict):
        self._last_data = result['data']
        self._last_suggested_name = os.path.basename(result['suggested_path'])
        self.result_edit.setPlainText(result['display'])
        encrypted = self._running_mode == 'encrypt'
        self.result_label.setText(
            'Encrypted text — copy and paste it into your chat' if encrypted
            else 'Decrypted message')
        self.copy_result.setText('Copy encrypted text' if encrypted else 'Copy decrypted text')
        plaintext = self._running_input if encrypted else result['display']
        ciphertext = result['display'] if encrypted else ''.join(self._running_input.split())

        if result.get('fingerprint'):
            identity = f"rsa:{result['fingerprint']}"
        else:
            identity = 'aes:' + hashlib.sha256(self.chat_password.text().encode('utf-8')).hexdigest()
        if (self.transcript and self._session_identity is not None
                and identity != self._session_identity):
            # A different password or key starts a fresh in-memory session.
            self.transcript.clear()
        self._session_identity = identity

        self.transcript.append({
            'ts': datetime.datetime.now().isoformat(timespec='seconds'),
            'direction': 'SENT' if encrypted else 'RECEIVED',
            'method': self._running_method,
            'plaintext': plaintext,
            'ciphertext_b64': ciphertext,
        })
        details = []
        if result.get('fingerprint'):
            details.append('Key SHA-256 fingerprint: ' + result['fingerprint'])
        details.append('Not saved yet. Use “Save text…” to choose a destination.')
        title = 'Text encrypted' if encrypted else 'Text decrypted'
        self.status.show_success(title, result['suggested_path'], '\n'.join(details))
        self.status.save_as_button.setText('Save text…')

    def _on_failure(self, message: str):
        # Don't leave the previous operation's result on screen next to an error.
        self._clear_result()
        self.status.show_error(message)

    def clear_transient_error(self):
        """Clear an old error while preserving successful operation results."""
        if self.status.property('state') == 'error':
            self.status.clear()

    def _clear_input(self):
        self.input_edit.clear()
        self.clear_transient_error()

    def _copy_result(self):
        text = self.result_edit.toPlainText()
        if not text:
            return
        if self._running_mode == 'decrypt':
            QGuiApplication.clipboard().setText(text)
            self._sensitive_clipboard_value = text
            self._clipboard_timer.start(core.CLIPBOARD_CLEAR_TIMEOUT * 1000)
            _flash_button_text(
                self.copy_result, f'Copied (clears in {core.CLIPBOARD_CLEAR_TIMEOUT}s)')
        else:
            QGuiApplication.clipboard().setText(text)
            _flash_button_text(self.copy_result, 'Copied')

    def _clear_sensitive_clipboard(self):
        expected = self._sensitive_clipboard_value
        if expected is None:
            return
        clipboard = QGuiApplication.clipboard()
        if clipboard.text() == expected:
            clipboard.clear()
        self._sensitive_clipboard_value = None

    def _clear_result(self):
        self.result_edit.clear()
        self.result_label.setText('Result')
        self.copy_result.setText('Copy result')
        self._last_data = None
        self._last_suggested_name = None

    def _end_session(self):
        self.transcript.clear()
        self._session_identity = None
        self._last_data = None
        self._last_suggested_name = None
        self.input_edit.clear()
        self.result_edit.clear()
        self.result_label.setText('Result')
        self.copy_result.setText('Copy result')
        self.chat_password.clear()
        self.public_key.clear()
        self.private_key.clear()
        self.private_password.clear()
        self.status.clear()

    def _paste_input(self):
        text = QGuiApplication.clipboard().text()
        if not text:
            self.status.show_error('The clipboard does not contain text.')
            return
        self.input_edit.setPlainText(text)
        self.clear_transient_error()

    def _load_from_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, 'Open encrypted Base64 text', TEXTS_DIR,
            'Encrypted Base64 text (*.txt)')
        if not path:
            return
        try:
            data = load_encrypted_text_file(path)
        except CryptoError as e:
            self.status.show_error(str(e))
            return
        self.input_edit.setPlainText(data)
        self.clear_transient_error()

    def _save_as(self):
        if self._last_data is None:
            return
        default_name = self._last_suggested_name or os.path.basename(self.status.path_edit.text())
        default_path = os.path.join(TEXTS_DIR, default_name)
        path, _ = QFileDialog.getSaveFileName(self, 'Save text', default_path,
                                               'Text files (*.txt);;All files (*)')
        if not path:
            return
        try:
            self._write_trace_file(path)
        except Exception as e:
            self.status.show_error(f'Could not save: {e}')
            log_operation('SAVE_TEXT', path, self._running_method.upper(), 'FAILED',
                          error='Output write failed', additional='save_text (gui)')
            return

        self.status.path_edit.setText(path)
        self.status.detail_label.setText(
            'Saved explicitly by the user, with the starting text and result together.')
        self.status.detail_label.setVisible(True)
        log_operation('SAVE_TEXT', path, self._running_method.upper(), 'SUCCESS',
                      additional='save_text (gui)')
        _flash_button_text(self.status.save_as_button, 'Saved')

    def _write_trace_file(self, path: str):
        """Write the starting text and the result together to the chosen path,
        for a complete record of this single operation. The saved file is no
        longer pure Base64/plaintext, so it can't be reloaded with 'Load
        encrypted Base64...' — that button is for Base64 text from elsewhere."""
        encrypted = self._running_mode == 'encrypt'
        try:
            result_text = self._last_data.decode('ascii' if encrypted else 'utf-8').rstrip('\n')
        except UnicodeDecodeError:
            result_text = '<binary data>'
        lines = [
            'File Secure Suite - saved text (full record)',
            f"Saved: {datetime.datetime.now().isoformat(timespec='seconds')}",
            f'Method: {self._running_method.upper()}',
            f"Direction: {'Encrypted for sending' if encrypted else 'Decrypted received text'}",
            '=' * 60, '',
            '-- Starting text (plaintext) --' if encrypted else '-- Starting text (encrypted, Base64) --',
            self._running_input, '',
            '-- Result (encrypted, Base64) --' if encrypted else '-- Result (decrypted plaintext) --',
            result_text, '',
        ]
        _write_atomic(path, '\n'.join(lines).encode('utf-8'))


class KeyResultCard(QFrame):
    """Show a generated key pair, its public-key QR, and saved paths."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName('resultCard')
        self.setVisible(False)
        self._qr_data: Optional[bytes] = None
        self._qr_path = ''
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)

        title_row = QHBoxLayout()
        self.title_label = QLabel('')
        self.title_label.setObjectName('statusTitle')
        title_row.addWidget(self.title_label)
        title_row.addStretch(1)
        self.open_folder_button = QPushButton('Open folder')
        self.open_folder_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.open_folder_button.clicked.connect(self._open_keys_folder)
        title_row.addWidget(self.open_folder_button)
        self.clear_button = QPushButton('Clear')
        self.clear_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_button.clicked.connect(self.clear)
        title_row.addWidget(self.clear_button)
        layout.addLayout(title_row)

        clear_note = QLabel(
            'Clear hides this view only; the key files on disk are not deleted.')
        clear_note.setObjectName('fieldNote')
        clear_note.setWordWrap(True)
        layout.addWidget(clear_note)

        self.fingerprint_label = QLabel('')
        self.fingerprint_label.setObjectName('fingerprint')
        self.fingerprint_label.setWordWrap(True)
        layout.addWidget(self.fingerprint_label)

        self.private_row = self._path_row('Private key')
        self.public_row = self._path_row('Public key')
        self.info_row = self._path_row('Key information')
        self.qr_row = self._path_row('Public key QR')
        layout.addWidget(self.private_row['widget'])
        layout.addWidget(self.public_row['widget'])
        layout.addWidget(self.info_row['widget'])
        layout.addWidget(self.qr_row['widget'])

        qr_heading = QLabel('Public key QR code')
        qr_heading.setObjectName('fieldLabel')
        layout.addWidget(qr_heading)
        self.qr_label = QLabel('')
        self.qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.qr_label.setMinimumHeight(280)
        layout.addWidget(self.qr_label)

        qr_actions = QHBoxLayout()
        qr_actions.addStretch(1)
        self.save_qr_button = QPushButton('Save QR image as…')
        self.save_qr_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.save_qr_button.clicked.connect(self._save_qr_as)
        qr_actions.addWidget(self.save_qr_button)
        qr_actions.addStretch(1)
        layout.addLayout(qr_actions)
        self.qr_feedback = QLabel('The QR contains the public key only.')
        self.qr_feedback.setObjectName('fieldNote')
        self.qr_feedback.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.qr_feedback.setWordWrap(True)
        layout.addWidget(self.qr_feedback)

        warn = QLabel('Private key security: keep it in a safe place. Anyone who has it can '
                      'decrypt everything encrypted for this key.')
        warn.setObjectName('fieldNote')
        warn.setWordWrap(True)
        layout.addWidget(warn)

    def _path_row(self, label_text: str) -> dict:
        row = QWidget()
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(6)
        label = QLabel(label_text)
        label.setObjectName('fieldLabel')
        label.setFixedWidth(120)
        edit = QLineEdit()
        edit.setReadOnly(True)
        h.addWidget(label)
        h.addWidget(edit, 1)
        return {'widget': row, 'edit': edit}

    def _open_keys_folder(self):
        path = self.private_row['edit'].text()
        if path:
            open_folder(os.path.dirname(path))

    def _save_qr_as(self):
        if not self._qr_data:
            return
        default_name = os.path.basename(self._qr_path) or 'public_key_qr.png'
        path, _ = QFileDialog.getSaveFileName(
            self, 'Save public key QR image', default_name, 'PNG image (*.png)')
        if not path:
            return
        if not path.lower().endswith('.png'):
            path += '.png'
        try:
            _write_atomic(path, self._qr_data)
        except Exception as e:
            self.qr_feedback.setProperty('state', 'error')
            self.qr_feedback.setText(f'Could not save the QR image: {e}')
        else:
            self.qr_feedback.setProperty('state', 'ok')
            self.qr_feedback.setText(f'QR image saved: {path}')
            _flash_button_text(self.save_qr_button, 'Saved')
        self.qr_feedback.style().unpolish(self.qr_feedback)
        self.qr_feedback.style().polish(self.qr_feedback)

    def show_result(self, result: dict):
        self.title_label.setText(f"Key “{result['keyname']}” generated")
        self.fingerprint_label.setProperty('state', 'ok')
        self.fingerprint_label.setText(f"SHA-256 fingerprint: {result['fingerprint']}")
        self.fingerprint_label.style().unpolish(self.fingerprint_label)
        self.fingerprint_label.style().polish(self.fingerprint_label)
        self.private_row['edit'].setText(result['private_file'])
        self.public_row['edit'].setText(result['public_file'])
        self.info_row['edit'].setText(result.get('info_file') or '')
        self.info_row['widget'].setVisible(bool(result.get('info_file')))
        self.qr_row['edit'].setText(result['qr_file'])
        self._qr_data = result['qr_data']
        self._qr_path = result['qr_file']
        pixmap = QPixmap()
        pixmap.loadFromData(self._qr_data, 'PNG')
        self.qr_label.setPixmap(pixmap.scaled(
            280, 280, Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.FastTransformation))
        self.qr_feedback.setProperty('state', 'ok')
        self.qr_feedback.setText('QR saved automatically. It contains the public key only.')
        self.qr_feedback.style().unpolish(self.qr_feedback)
        self.qr_feedback.style().polish(self.qr_feedback)
        self.save_qr_button.setText('Save QR image as…')
        self.setVisible(True)

    def clear(self):
        """Reset this view only. Does not touch the key files already saved to disk."""
        self.title_label.clear()
        self.fingerprint_label.clear()
        self.fingerprint_label.setProperty('state', '')
        self.fingerprint_label.style().unpolish(self.fingerprint_label)
        self.fingerprint_label.style().polish(self.fingerprint_label)
        for row in (self.private_row, self.public_row, self.info_row, self.qr_row):
            row['edit'].clear()
        self.qr_label.clear()
        self._qr_data = None
        self._qr_path = ''
        self.qr_feedback.setProperty('state', '')
        self.qr_feedback.setText('The QR contains the public key only.')
        self.qr_feedback.style().unpolish(self.qr_feedback)
        self.qr_feedback.style().polish(self.qr_feedback)
        self.save_qr_button.setText('Save QR image as…')
        self.setVisible(False)


class GenerateKeyCard(QFrame):
    """The generation form: name, optional password, generate — runs off
    the GUI thread since RSA-4096 generation can take a while on a slow
    or entropy-starved machine."""

    generated = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName('card')
        self._thread: Optional[QThread] = None
        self._worker: Optional[Worker] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(10)

        title = QLabel('Generate a new key pair')
        title.setObjectName('cardTitle')
        layout.addWidget(title)

        name_label = QLabel('Key name')
        name_label.setObjectName('fieldLabel')
        layout.addWidget(name_label)
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText('for example "work" or "alice"')
        layout.addWidget(self.name_edit)

        self.protect_toggle = QPushButton('Protect the private key with a password')
        self.protect_toggle.setObjectName('checkToggle')
        self.protect_toggle.setCheckable(True)
        self.protect_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.protect_toggle.toggled.connect(self._on_protect_toggled)
        layout.addWidget(self.protect_toggle)
        protect_note = QLabel(
            'Turn it off to generate an unprotected key (hides the password fields).')
        protect_note.setObjectName('fieldNote')
        protect_note.setWordWrap(True)
        layout.addWidget(protect_note)

        self.password_area = QWidget()
        pw_layout = QVBoxLayout(self.password_area)
        pw_layout.setContentsMargins(0, 0, 0, 0)
        pw_layout.setSpacing(8)
        self.password_field = PasswordField('Private key password')
        pw_layout.addWidget(self.password_field)
        self.confirm_field = PasswordField('Repeat the password')
        pw_layout.addWidget(self.confirm_field)
        self.key_password_hint = KeyPasswordHint(self.password_field, self.confirm_field)
        pw_layout.addWidget(self.key_password_hint)
        self.password_area.setVisible(True)
        layout.addWidget(self.password_area)

        self.generate_button = QPushButton('Generate key pair')
        self.generate_button.setObjectName('primaryButton')
        self.generate_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.generate_button.setEnabled(False)
        self.generate_button.clicked.connect(self._run)
        layout.addWidget(self.generate_button)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.hint_label = QLabel('')
        self.hint_label.setObjectName('fieldNote')
        self.hint_label.setVisible(False)
        self.hint_label.setWordWrap(True)
        layout.addWidget(self.hint_label)

        self.result = KeyResultCard()
        layout.addWidget(self.result)

        self.name_edit.textChanged.connect(self._validate)
        self.password_field.edit.textChanged.connect(self._validate)
        self.confirm_field.edit.textChanged.connect(self._validate)
        self.protect_toggle.setChecked(True)

    def _on_protect_toggled(self, checked: bool):
        self.password_area.setVisible(checked)
        self._validate()

    def _validate(self):
        ok = bool(self.name_edit.text().strip())
        if self.protect_toggle.isChecked():
            ok = ok and self.key_password_hint.refresh()
        self.generate_button.setEnabled(ok and self._thread is None)

    def _run(self):
        keyname = self.name_edit.text().strip()
        password = self.password_field.text() if self.protect_toggle.isChecked() else None
        if password is None:
            answer = QMessageBox.question(
                self, 'Generate an unprotected private key?',
                'The private key will be saved without password protection. Anyone who '
                'obtains the file can use it immediately. Continue?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if answer != QMessageBox.StandardButton.Yes:
                return

        self.result.setVisible(False)
        self.progress.setVisible(True)
        self.hint_label.setProperty('state', '')
        self.hint_label.style().unpolish(self.hint_label)
        self.hint_label.style().polish(self.hint_label)
        self.hint_label.setText('Generating the RSA-4096 key pair — this may take '
                                'up to a couple of minutes on some computers…')
        self.hint_label.setVisible(True)
        self.generate_button.setEnabled(False)

        self._thread = QThread(self)
        self._worker = Worker(generate_keypair, dict(keyname=keyname, password=password))
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.succeeded.connect(self._on_success)
        self._worker.failed.connect(self._on_failure)
        self._worker.succeeded.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(self._cleanup)
        self._thread.start()

    def _cleanup(self):
        self._thread = None
        self._worker = None
        self.progress.setVisible(False)
        self._validate()

    def _on_success(self, result: dict):
        self.hint_label.setVisible(False)
        self.result.show_result(result)
        self.name_edit.clear()
        self.password_field.clear()
        self.confirm_field.clear()
        self.protect_toggle.setChecked(True)
        self.generated.emit(result)

    def _on_failure(self, message: str):
        self.hint_label.setProperty('state', 'error')
        self.hint_label.setText(message)
        self.hint_label.setVisible(True)
        self.hint_label.style().unpolish(self.hint_label)
        self.hint_label.style().polish(self.hint_label)


class KeysPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(16)

        heading = QLabel('Key Generation')
        heading.setObjectName('panelHeading')
        subheading = QLabel('<b>Generate a new RSA-4096 key pair.</b>')
        subheading.setObjectName('panelSubheading')
        subheading.setWordWrap(True)
        heading_row = QHBoxLayout()
        heading_row.addWidget(heading)
        heading_row.addStretch(1)
        root.addLayout(heading_row)
        root.addWidget(subheading)

        self.credentials_warning = QLabel(
            '⚠ If you forget the password or lose the private key, the data cannot '
            'be recovered — there is no backdoor or master key.')
        self.credentials_warning.setObjectName('fieldNote')
        self.credentials_warning.setProperty('state', 'weak')
        self.credentials_warning.setWordWrap(True)
        root.addWidget(self.credentials_warning)
        self.credentials_warning.style().unpolish(self.credentials_warning)
        self.credentials_warning.style().polish(self.credentials_warning)

        self.key_storage_warning = QLabel(
            '⚠ Keep the private key file and its password in separate, secure '
            'places — anyone who has both can decrypt everything protected by this key.')
        self.key_storage_warning.setObjectName('fieldNote')
        self.key_storage_warning.setProperty('state', 'weak')
        self.key_storage_warning.setWordWrap(True)
        root.addWidget(self.key_storage_warning)
        self.key_storage_warning.style().unpolish(self.key_storage_warning)
        self.key_storage_warning.style().polish(self.key_storage_warning)

        self.result_note = QLabel(
            'Only the most recent result is shown, and it clears automatically when '
            'you leave this page.')
        self.result_note.setObjectName('fieldNote')
        self.result_note.setWordWrap(True)
        root.addWidget(self.result_note)

        self.generate_card = GenerateKeyCard()
        root.addWidget(self.generate_card)
        root.addStretch(1)


class KeyManagementPanel(QWidget):
    """Back up keys and export a public key from a private key."""

    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(16)

        heading = QLabel('Key Management')
        heading.setObjectName('panelHeading')
        root.addWidget(heading)
        subtitle = QLabel('<b>Export a public key from a private key or back up RSA keys.</b>')
        subtitle.setObjectName('panelSubheading')
        subtitle.setWordWrap(True)
        root.addWidget(subtitle)
        open_backup_row = QHBoxLayout()
        open_backup_row.addStretch(1)
        open_backup = QPushButton('Open backup folder')
        open_backup.clicked.connect(lambda: open_folder(BACKUP_DIR))
        open_backup_row.addWidget(open_backup)
        root.addLayout(open_backup_row)

        export_card = QFrame()
        export_card.setObjectName('card')
        export_layout = QVBoxLayout(export_card)
        export_title = QLabel('Export public key from private key')
        export_title.setObjectName('cardTitle')
        export_layout.addWidget(export_title)
        self.private_picker = KeyPicker(
            'Load private key…', 'Choose the private key', mode='private')
        export_layout.addWidget(self.private_picker)
        self.private_password = PasswordField('Private key password (optional)')
        export_layout.addWidget(self.private_password)
        self.export_button = QPushButton('Export public key')
        self.export_button.setObjectName('primaryButton')
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self._export)
        export_layout.addWidget(self.export_button)
        root.addWidget(export_card)

        backup_card = QFrame()
        backup_card.setObjectName('card')
        backup_layout = QVBoxLayout(backup_card)
        backup_title = QLabel('Back up keys')
        backup_title.setObjectName('cardTitle')
        backup_layout.addWidget(backup_title)
        backup_note = QLabel(
            'Copies remain protected. Use the default backup folder beside the '
            'application, or choose another folder.')
        backup_note.setObjectName('fieldNote')
        backup_note.setWordWrap(True)
        backup_layout.addWidget(backup_note)
        backup_buttons = QHBoxLayout()
        backup_selected = QPushButton('Choose keys to back up…')
        backup_selected.clicked.connect(self._choose_keys)
        backup_buttons.addWidget(backup_selected)
        backup_buttons.addStretch(1)
        backup_layout.addLayout(backup_buttons)

        # Keys chosen with "Choose keys to back up…" are listed here and only
        # backed up after the user confirms with "Back up selected keys".
        self._selected_keys: list = []
        self._key_chips: dict = {}
        self.selected_keys_layout = QVBoxLayout()
        self.selected_keys_layout.setSpacing(6)
        selected_keys_widget = QWidget()
        selected_keys_widget.setLayout(self.selected_keys_layout)
        backup_layout.addWidget(selected_keys_widget)
        self.selected_keys_note = QLabel(
            'Review the selected keys, then confirm the backup with the button below. '
            'Remove one with ✕.')
        self.selected_keys_note.setObjectName('fieldNote')
        self.selected_keys_note.setWordWrap(True)
        self.selected_keys_note.setVisible(False)
        backup_layout.addWidget(self.selected_keys_note)
        confirm_row = QHBoxLayout()
        confirm_row.addStretch(1)
        self.clear_selected_button = QPushButton('Clear selection')
        self.clear_selected_button.clicked.connect(self._clear_selected_keys)
        self.backup_selected_button = QPushButton('Back up selected keys')
        self.backup_selected_button.setObjectName('primaryButton')
        self.backup_selected_button.clicked.connect(self._backup_selected)
        confirm_row.addWidget(self.clear_selected_button)
        confirm_row.addWidget(self.backup_selected_button)
        self.confirm_row_widget = QWidget()
        self.confirm_row_widget.setLayout(confirm_row)
        self.confirm_row_widget.setVisible(False)
        backup_layout.addWidget(self.confirm_row_widget)
        root.addWidget(backup_card)

        self.status = StatusStrip()
        self.status.clear_button.setVisible(True)
        self.status.clear_button.clicked.connect(self._clear_result)
        # Exports are saved automatically in the backup folder; "Open folder"
        # is enough, so there is no "Save as" here.
        self.status.save_as_button.setVisible(False)
        root.addWidget(self.status)
        root.addStretch(1)
        self.private_picker.changed.connect(
            lambda: self.export_button.setEnabled(bool(self.private_picker.pem_text)))
        # Removing the key also wipes the password typed for it.
        self.private_picker.clear_button.clicked.connect(self.private_password.clear)

    def _clear_result(self):
        self.status.clear()

    def reset(self):
        """Wipe everything on this page (key, password, result, backup selection).
        Called when the user navigates away. Key files on disk are untouched."""
        self.private_picker.clear()
        self.private_password.clear()
        self.status.clear()
        self._clear_selected_keys()

    def _show_backup(self, result: dict):
        first = result['files'][0]
        count = result['count']
        key_label = 'key' if count == 1 else 'keys'
        self.status.show_success(
            f'OK — {count} {key_label} copied', first,
            f"Backup folder: {result['directory']}")

    def _choose_keys(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, 'Choose keys to back up', KEYS_DIR,
            'PEM keys (*.pem);;All files (*)')
        if not paths:
            return
        keys_dir = os.path.normcase(os.path.realpath(KEYS_DIR))
        rejected = 0
        for raw in paths:
            path = os.path.abspath(raw)
            parent = os.path.normcase(os.path.realpath(os.path.dirname(path)))
            if parent != keys_dir or not path.lower().endswith('.pem'):
                rejected += 1
                continue
            if path in self._selected_keys:
                continue
            self._selected_keys.append(path)
            chip = FileChip(badge='KEY')
            chip.set_file(path)
            chip.cleared.connect(lambda p=path: self._remove_selected_key(p))
            self.selected_keys_layout.addWidget(chip)
            self._key_chips[path] = chip
        self._sync_selected_keys()
        if rejected:
            self.status.show_error(
                f'{rejected} file(s) not added: only .pem keys from the application '
                f'keys folder can be backed up.')
        else:
            self.status.setVisible(False)

    def _remove_selected_key(self, path: str):
        if path in self._selected_keys:
            self._selected_keys.remove(path)
        chip = self._key_chips.pop(path, None)
        if chip is not None:
            self.selected_keys_layout.removeWidget(chip)
            chip.deleteLater()
        self._sync_selected_keys()

    def _clear_selected_keys(self):
        for path in list(self._selected_keys):
            self._remove_selected_key(path)

    def _sync_selected_keys(self):
        has_keys = bool(self._selected_keys)
        self.selected_keys_note.setVisible(has_keys)
        self.confirm_row_widget.setVisible(has_keys)
        n = len(self._selected_keys)
        self.backup_selected_button.setText(
            'Back up selected key' if n == 1 else 'Back up selected keys')

    def _backup_selected(self):
        if not self._selected_keys:
            return
        try:
            self._show_backup(backup_keys(list(self._selected_keys)))
        except Exception as e:
            self.status.show_error(str(e))
            return
        self._clear_selected_keys()

    def _export(self):
        try:
            result = export_public_key(
                self.private_picker.path_edit.text(), self.private_password.text() or None)
        except Exception as e:
            self.status.show_error(str(e))
            return
        self.status.show_success('Public key exported', result['path'],
                                 f"SHA-256 fingerprint: {result['fingerprint']}")


class AuditLogPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._full_log = ''
        root = QVBoxLayout(self)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(14)
        heading = QLabel('Audit log')
        heading.setObjectName('panelHeading')
        root.addWidget(heading)
        note = QLabel('<b>Metadata only: plaintext, passwords, and key contents are never logged.</b>')
        note.setObjectName('panelSubheading')
        note.setWordWrap(True)
        root.addWidget(note)
        log_buttons = QHBoxLayout()
        log_buttons.addStretch(1)
        refresh = QPushButton('Refresh')
        refresh.clicked.connect(self.refresh)
        log_buttons.addWidget(refresh)
        open_logs = QPushButton('Open logs folder')
        open_logs.clicked.connect(lambda: open_folder(LOG_DIR))
        log_buttons.addWidget(open_logs)
        root.addLayout(log_buttons)
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText('Filter (e.g. FAILED, RSA, DECRYPT)…')
        self.filter_edit.textChanged.connect(self._apply_filter)
        root.addWidget(self.filter_edit)
        self.viewer = QPlainTextEdit()
        self.viewer.setReadOnly(True)
        self.viewer.setObjectName('auditViewer')
        root.addWidget(self.viewer, 1)
        self.refresh()

    def refresh(self):
        self._full_log = get_audit_log()
        self._apply_filter()

    def _apply_filter(self):
        query = self.filter_edit.text().strip().lower()
        if not query:
            shown = self._full_log
        else:
            matches = [line for line in self._full_log.splitlines() if query in line.lower()]
            shown = '\n'.join(matches) if matches else '(no entries match this filter)'
        self.viewer.setPlainText(shown)
        # Jump to the most recent entries rather than leaving the view at the top.
        scrollbar = self.viewer.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())


def _soft_wrap(text: str, every: int = 10) -> str:
    """Insert zero-width spaces every N characters so QLabel word-wrap can
    break a single long unbroken token (like an LNURL string) instead of
    forcing the whole layout wide. Purely cosmetic — callers that need the
    real value (e.g. to copy to the clipboard) must keep using the original
    string, not this wrapped copy."""
    return '\u200b'.join(text[i:i + every] for i in range(0, len(text), every))


def credits_qr_pixmap(module_size: int = 5) -> QPixmap:
    quiet = 4
    side = (len(CREDITS_QR_MATRIX) + quiet * 2) * module_size
    image = QImage(side, side, QImage.Format.Format_RGB32)
    image.fill(0xffffffff)
    for row, bits in enumerate(CREDITS_QR_MATRIX):
        for column, bit in enumerate(bits):
            if bit == '1':
                x0 = (column + quiet) * module_size
                y0 = (row + quiet) * module_size
                for y in range(y0, y0 + module_size):
                    for x in range(x0, x0 + module_size):
                        image.setPixel(x, y, 0xff000000)
    return QPixmap.fromImage(image)


class CreditsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(12)
        heading = QLabel('About')
        heading.setObjectName('panelHeading')
        root.addWidget(heading)
        description = QLabel(
            '<b>File Secure Suite is an open-source encryption utility using '
            'AES-256-GCM, RSA-4096 with OAEP, PBKDF2-SHA-256, authenticated FSS2 '
            'containers, and OpenSSL-compatible PKCS#8 keys. Batches of up to 5 files '
            '(combined up to 1 GiB) and text up to 1 MiB are supported, subject to '
            'available memory.</b>')
        description.setObjectName('panelSubheading')
        description.setWordWrap(True)
        root.addWidget(description)
        features = QLabel(
            'Key features\n'
            '• RSA-4096 key generation, backup, and public-key export\n'
            '• Password-based and hybrid public-key encryption\n'
            '• FSS1 legacy decryption and FSS2 authenticated encryption\n'
            '• In-memory text sessions and metadata-only audit logging')
        features.setWordWrap(True)
        root.addWidget(features)
        root.addSpacing(18)
        responsible_use_title = QLabel('A note on responsible use')
        responsible_use_title.setObjectName('cardTitle')
        root.addWidget(responsible_use_title)
        responsible_use = QLabel(
            'File Secure Suite is a neutral tool, like a lock or a pen: it can be used '
            'well or poorly, and that choice belongs entirely to the person using it. '
            'It exists to protect privacy — for private conversations, sensitive '
            'documents, and personal data — not to enable harm. Please use it '
            'responsibly and lawfully, and extend that same respect to others’ '
            'privacy. As open-source software, it is provided as-is, without warranty, '
            'and its author accepts no liability for how others choose to use it.')
        responsible_use.setObjectName('fieldNote')
        responsible_use.setWordWrap(True)
        root.addWidget(responsible_use)
        root.addSpacing(18)
        quote = QLabel(
            '<i>Secret is what you hide.<br>'
            'Private is what you choose to reveal.<br>'
            'Privacy is the power to selectively reveal oneself to the world.<br>'
            'You don’t need something to hide to need privacy.</i>')
        quote.setObjectName('fieldNote')
        quote.setWordWrap(True)
        root.addWidget(quote)
        attribution = QLabel('Inspired by Eric Hughes, A Cypherpunk’s Manifesto, 1993')
        attribution.setObjectName('fieldNote')
        attribution.setWordWrap(True)
        root.addWidget(attribution)
        root.addSpacing(18)
        support = QLabel('Support the project with a Lightning Network donation')
        support.setObjectName('cardTitle')
        root.addWidget(support)
        donation_card = QFrame()
        donation_card.setObjectName('card')
        donation_row = QHBoxLayout(donation_card)
        qr = QLabel()
        qr.setPixmap(credits_qr_pixmap(module_size=4))
        donation_row.addWidget(qr, 0, Qt.AlignmentFlag.AlignTop)
        donation_info = QVBoxLayout()
        address = QLabel(_soft_wrap(CREDITS_LNURL))
        address.setObjectName('fingerprint')
        address.setWordWrap(True)
        address.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        donation_info.addWidget(address)
        self.copy_address_button = QPushButton('Copy Lightning address')
        self.copy_address_button.clicked.connect(self._copy_address)
        donation_info.addWidget(self.copy_address_button)
        donation_info.addStretch(1)
        donation_row.addLayout(donation_info, 1)
        root.addWidget(donation_card)
        root.addStretch(1)

    def _copy_address(self):
        QGuiApplication.clipboard().setText(CREDITS_LNURL)
        _flash_button_text(self.copy_address_button, 'Copied')


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f'File Secure Suite — GUI v{APP_VERSION}')
        screen = QGuiApplication.primaryScreen()
        available = screen.availableGeometry() if screen else None
        initial_width = min(1050, int(available.width() * 0.9)) if available else 980
        initial_height = min(820, int(available.height() * 0.9)) if available else 780
        self.resize(max(560, initial_width), max(420, initial_height))
        self.setMinimumSize(560, 420)

        central = QWidget()
        self.setCentralWidget(central)
        outer = QHBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        sidebar = QWidget()
        sidebar.setObjectName('sidebar')
        sidebar.setMinimumWidth(145)
        sidebar.setMaximumWidth(300)
        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(16, 24, 16, 16)
        side_layout.setSpacing(6)

        app_label = QLabel('File Secure Suite')
        app_label.setObjectName('appLabel')
        app_label.setWordWrap(True)
        side_layout.addWidget(app_label)
        suite_caption = QLabel('FILE & MESSAGE\nPRIVATE ENCRYPTION')
        suite_caption.setObjectName('sidebarCaption')
        suite_caption.setWordWrap(True)
        side_layout.addWidget(suite_caption)
        side_layout.addSpacing(20)

        self.nav_keys = QPushButton('Key Generation')
        self.nav_keys.setObjectName('navItem')
        self.nav_keys.setCheckable(True)
        self.nav_keys.setChecked(True)
        self.nav_keys.setCursor(Qt.CursorShape.PointingHandCursor)

        self.nav_text = QPushButton('Text')
        self.nav_text.setObjectName('navItem')
        self.nav_text.setCheckable(True)
        self.nav_text.setCursor(Qt.CursorShape.PointingHandCursor)

        self.nav_file = QPushButton('File')
        self.nav_file.setObjectName('navItem')
        self.nav_file.setCheckable(True)
        self.nav_file.setCursor(Qt.CursorShape.PointingHandCursor)

        self.nav_management = QPushButton('Key Management')
        self.nav_management.setObjectName('navItem')
        self.nav_management.setCheckable(True)
        self.nav_management.setCursor(Qt.CursorShape.PointingHandCursor)

        self.nav_audit = QPushButton('Audit log')
        self.nav_audit.setObjectName('navItem')
        self.nav_audit.setCheckable(True)
        self.nav_audit.setCursor(Qt.CursorShape.PointingHandCursor)

        self.nav_credits = QPushButton('About')
        self.nav_credits.setObjectName('navItem')
        self.nav_credits.setCheckable(True)
        self.nav_credits.setCursor(Qt.CursorShape.PointingHandCursor)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self.nav_group.addButton(self.nav_keys)
        self.nav_group.addButton(self.nav_text)
        self.nav_group.addButton(self.nav_file)
        self.nav_group.addButton(self.nav_management)
        self.nav_group.addButton(self.nav_audit)
        self.nav_group.addButton(self.nav_credits)

        for b in (self.nav_keys, self.nav_text, self.nav_file,
                  self.nav_management, self.nav_audit, self.nav_credits):
            b.setMinimumHeight(42)
            side_layout.addWidget(b)

        side_layout.addStretch(1)
        version_label = QLabel(f'GUI {APP_VERSION}\nCore {core.CORE_VERSION}')
        version_label.setObjectName('versionLabel')
        version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        side_layout.addWidget(version_label)

        self.stack = QStackedWidget()
        self.keys_panel = KeysPanel()
        self.text_panel = ChatTextPanel()
        self.file_panel = FilePanel()
        self.management_panel = KeyManagementPanel()
        self.audit_panel = AuditLogPanel()
        self.credits_panel = CreditsPanel()
        self.keys_page = self._scroll_page(self.keys_panel)
        self.text_page = self._scroll_page(self.text_panel)
        self.file_page = self._scroll_page(self.file_panel)
        self.management_page = self._scroll_page(self.management_panel)
        self.audit_page = self._scroll_page(self.audit_panel)
        self.credits_page = self._scroll_page(self.credits_panel)
        for page in (self.keys_page, self.text_page, self.file_page,
                     self.management_page, self.audit_page, self.credits_page):
            self.stack.addWidget(page)
        self._last_stack_page: Optional[QWidget] = self.stack.currentWidget()
        self.stack.currentChanged.connect(self._on_stack_changed)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.setChildrenCollapsible(False)
        self.splitter.addWidget(sidebar)
        self.splitter.addWidget(self.stack)
        self.splitter.setStretchFactor(0, 0)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.setSizes([190, max(370, initial_width - 190)])
        outer.addWidget(self.splitter, 1)

        self.nav_keys.toggled.connect(
            lambda checked: checked and self.stack.setCurrentWidget(self.keys_page))
        self.nav_text.toggled.connect(self._show_text)
        self.nav_file.toggled.connect(
            lambda checked: checked and self.stack.setCurrentWidget(self.file_page))
        self.nav_management.toggled.connect(
            lambda checked: checked and self.stack.setCurrentWidget(self.management_page))
        self.nav_audit.toggled.connect(self._show_audit)
        self.nav_credits.toggled.connect(
            lambda checked: checked and self.stack.setCurrentWidget(self.credits_page))

    @staticmethod
    def _scroll_page(panel: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(panel)
        return scroll

    def _show_audit(self, checked: bool):
        if checked:
            self.audit_panel.refresh()
            self.stack.setCurrentWidget(self.audit_page)

    def _show_text(self, checked: bool):
        if checked:
            self.text_panel.clear_transient_error()
            self.stack.setCurrentWidget(self.text_page)

    def _on_stack_changed(self, _index: int):
        if self._last_stack_page is self.keys_page and self.stack.currentWidget() is not self.keys_page:
            self.keys_panel.generate_card.result.clear()
        if (self._last_stack_page is self.management_page
                and self.stack.currentWidget() is not self.management_page):
            self.management_panel.reset()
        self._last_stack_page = self.stack.currentWidget()

# Point sizes avoid invalid font metrics on some Qt platforms.
APP_STYLESHEET = """
* {
    font-family: "Inter", "Segoe UI Variable Text", "Segoe UI", "SF Pro Text", "Noto Sans", sans-serif;
    font-size: 10.5pt;
    color: #172033;
}
QMainWindow, QWidget {
    background-color: #f4f7fb;
}
#sidebar {
    background-color: #0f172a;
    border-right: 1px solid #1e293b;
}
#appLabel {
    background: transparent;
    font-size: 15pt;
    font-weight: 700;
    color: #ffffff;
}
#sidebarCaption {
    background: transparent;
    font-size: 8pt;
    font-weight: 700;
    letter-spacing: 1px;
    color: #7dd3fc;
}
#versionLabel {
    background: transparent;
    font-size: 8.5pt;
    color: #94a3b8;
}
QSplitter::handle {
    background-color: #dbe3ec;
    width: 5px;
}
QSplitter::handle:hover {
    background-color: #60a5fa;
}
QPushButton#navItem, QPushButton#navDisabled {
    text-align: left;
    padding: 10px 14px;
    border-radius: 8px;
    border: none;
    background: transparent;
    color: #cbd5e1;
    font-size: 10.5pt;
    font-weight: 600;
}
QPushButton#navItem:hover {
    background-color: #1e293b;
    color: #ffffff;
}
QPushButton#navItem:checked {
    background-color: #2563eb;
    color: #ffffff;
    font-weight: 700;
}
QPushButton#navDisabled {
    color: #64748b;
}
#panelHeading {
    font-size: 21pt;
    font-weight: 700;
    color: #0f172a;
}
#panelSubheading {
    font-size: 10.5pt;
    color: #64748b;
}
#phaseBadge {
    background-color: #dbeafe;
    color: #1d4ed8;
    border: 1px solid #bfdbfe;
    border-radius: 10px;
    padding: 3px 11px;
    font-size: 9pt;
    font-weight: 700;
}
#fieldLabel {
    font-size: 10pt;
    font-weight: 700;
    color: #334155;
    margin-top: 6px;
}
#fieldNote {
    font-size: 9.5pt;
    color: #64748b;
}
#fieldNote[state="error"] {
    color: #b42318;
    font-weight: 600;
}
#fieldNote[state="ok"] {
    color: #067647;
    font-weight: 600;
}
#fieldNote[state="weak"] {
    color: #b45309;
    font-weight: 600;
}
#cardTitle {
    font-size: 12pt;
    font-weight: 700;
    color: #0f172a;
}
#card, #resultCard {
    background-color: #ffffff;
    border: 1px solid #d8e0ea;
    border-radius: 12px;
}
#modeToggle {
    background-color: #e8eef6;
    border: 1px solid #d8e0ea;
    border-radius: 10px;
    padding: 3px;
}
QPushButton#modeLeft, QPushButton#modeRight {
    border: none;
    background: transparent;
    padding: 9px 24px;
    border-radius: 7px;
    color: #64748b;
    font-weight: 700;
    font-size: 10.5pt;
}
QPushButton#modeLeft:hover, QPushButton#modeRight:hover {
    color: #1d4ed8;
}
QPushButton#modeLeft:checked, QPushButton#modeRight:checked {
    background-color: #2563eb;
    color: #ffffff;
}
QPushButton#checkToggle {
    text-align: left;
    background-color: #f8fafc;
    border: 1px solid #d8e0ea;
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 10pt;
    font-weight: 600;
    color: #334155;
}
QPushButton#checkToggle:hover {
    border-color: #93c5fd;
    color: #1d4ed8;
}
QPushButton#checkToggle:checked {
    background-color: #eff6ff;
    border-color: #60a5fa;
    color: #1d4ed8;
}
#dropZone {
    background-color: #f8fafc;
    border: 2px dashed #b8c5d4;
    border-radius: 12px;
    padding: 20px;
}
#dropZone[dragActive="true"] {
    border: 2px dashed #2563eb;
    background-color: #eff6ff;
}
#dropIcon {
    font-size: 25pt;
    font-weight: 300;
    color: #3b82f6;
}
#dropHint {
    font-size: 13pt;
    font-weight: 700;
    color: #0f172a;
}
#dropSub {
    font-size: 10pt;
    color: #64748b;
}
QPushButton#browseButton {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    padding: 9px 18px;
    font-weight: 700;
    font-size: 10pt;
}
QPushButton#browseButton:hover {
    border-color: #60a5fa;
    color: #1d4ed8;
    background-color: #eff6ff;
}
#fileChip {
    background-color: #ffffff;
    border: 1px solid #d8e0ea;
    border-radius: 9px;
}
#fileTypeBadge {
    background-color: #dbeafe;
    color: #1d4ed8;
    border-radius: 5px;
    padding: 4px 6px;
    font-size: 7.5pt;
    font-weight: 800;
}
#fileChipName {
    font-weight: 700;
    font-size: 10.5pt;
    color: #172033;
}
#fileChipSize {
    color: #64748b;
    font-size: 9.5pt;
}
QToolButton#fileChipRemove {
    border: none;
    background: transparent;
    color: #64748b;
    font-weight: 700;
    font-size: 12pt;
    padding: 2px 8px;
}
QToolButton#fileChipRemove:hover {
    color: #b42318;
    background-color: #fef2f2;
}
QLineEdit, QComboBox, QPlainTextEdit {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    padding: 9px 11px;
    font-size: 10pt;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
}
QLineEdit:hover, QComboBox:hover, QPlainTextEdit:hover {
    border-color: #94a3b8;
}
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus {
    border: 1.5px solid #3b82f6;
}
QLineEdit[readOnly="true"] {
    color: #475569;
    background-color: #f8fafc;
}
QComboBox::drop-down {
    border: none;
    width: 28px;
}
QComboBox QAbstractItemView {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    selection-background-color: #dbeafe;
    selection-color: #1e3a8a;
    padding: 4px;
}
QToolButton {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 10pt;
}
QToolButton:hover {
    border-color: #60a5fa;
    color: #1d4ed8;
}
QToolButton:checked {
    border-color: #60a5fa;
    color: #1d4ed8;
    background-color: #eff6ff;
}
#fingerprint {
    font-family: "Cascadia Mono", "SFMono-Regular", "Consolas", "Noto Sans Mono", monospace;
    font-size: 9pt;
    color: #64748b;
}
#fingerprint[state="ok"] {
    color: #0f766e;
}
#fingerprint[state="error"] {
    color: #b42318;
}
QPushButton#primaryButton {
    background-color: #2563eb;
    color: #ffffff;
    border: 1px solid #2563eb;
    border-radius: 9px;
    padding: 13px;
    font-size: 11.5pt;
    font-weight: 700;
    margin-top: 6px;
}
QPushButton#primaryButton:hover {
    background-color: #1d4ed8;
    border-color: #1d4ed8;
    color: #ffffff;
}
QPushButton#primaryButton:pressed {
    background-color: #1e40af;
    border-color: #1e40af;
}
QPushButton#primaryButton:disabled {
    background-color: #e2e8f0;
    border-color: #e2e8f0;
    color: #94a3b8;
}
QProgressBar {
    background-color: #dbe3ec;
    border: none;
    border-radius: 4px;
    height: 8px;
    color: transparent;
}
QProgressBar::chunk {
    background-color: #2563eb;
    border-radius: 4px;
}
#statusStrip {
    border-radius: 10px;
    padding: 2px;
}
#statusStrip[state="success"] {
    background-color: #ecfdf5;
    border: 1px solid #a7f3d0;
}
#statusStrip[state="error"] {
    background-color: #fef2f2;
    border: 1px solid #fecaca;
}
#statusTitle {
    font-weight: 700;
    font-size: 11.5pt;
    color: #0f172a;
}
#statusStrip[state="success"] #statusTitle {
    color: #047857;
}
#statusStrip[state="error"] #statusTitle {
    color: #b42318;
}
#statusDetail {
    color: #475569;
    font-size: 9.5pt;
}
QPushButton {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    padding: 9px 14px;
    font-size: 10pt;
    font-weight: 600;
}
QPushButton:hover {
    border-color: #60a5fa;
    color: #1d4ed8;
    background-color: #f8fbff;
}
QPushButton:pressed {
    background-color: #eff6ff;
}
QPushButton:disabled {
    background-color: #f1f5f9;
    color: #94a3b8;
    border-color: #e2e8f0;
}
QScrollArea {
    border: none;
    background: transparent;
}
QScrollArea > QWidget > QWidget {
    background-color: #f4f7fb;
}
QScrollBar:vertical {
    background: transparent;
    width: 20px;
    margin: 2px;
}
QScrollBar::handle:vertical {
    background: #b8c5d4;
    border-radius: 9px;
    min-height: 36px;
}
QScrollBar::handle:vertical:hover {
    background: #94a3b8;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar:horizontal {
    background: transparent;
    height: 20px;
    margin: 2px;
}
QScrollBar::handle:horizontal {
    background: #b8c5d4;
    border-radius: 9px;
    min-width: 36px;
}
QScrollBar::handle:horizontal:hover {
    background: #94a3b8;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
"""


def main():
    _cleanup_stale_temp_files()
    app = QApplication(sys.argv)
    base_font = QFont('Segoe UI', 10)
    base_font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    app.setFont(base_font)
    app.setStyleSheet(APP_STYLESHEET)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
