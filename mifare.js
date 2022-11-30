/**
*  ---------
* |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
* |#       #|  
* |#       #|  Copyright (c) 1999-2011 CardContact Software & System Consulting
* |'##> <##'|  Andreas Schwier, 32429 Minden, Germany (www.cardcontact.de)
*  --------- 
*
*  This file is part of OpenSCDP.
*
*  OpenSCDP is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License version 2 as
*  published by the Free Software Foundation.
*
*  OpenSCDP is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with OpenSCDP; if not, write to the Free Software
*  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*
* @fileoverview Script classes to access Mifare cards
*/

 
/**
* Create a Mifare card object
* @class Class encapsulating access to a Mifare classic 1K/4K card
* @constructor 
* @param {card} card the card object
*/
function Mifare(card) {
 	this.card = card;
}

/**
41  * Identifier for Key A
42  */
43 Mifare.KEY_A = 0x60;
44 
45 /**
46  * Identifier for Key B
47  */
48 Mifare.KEY_B = 0x61;
49 
50 /**
51  * Mifare Public Key Values
52  */
53 Mifare.PUBLICKEYS = [
54 	new ByteString("FFFFFFFFFFFF", HEX),	// Empty cards
55 	new ByteString("A0A1A2A3A4A5", HEX),	// MAD Key A
56 	new ByteString("B0B1B2B3B4B5", HEX),	// Default Key B
57 	new ByteString("D3F7D3F7D3F7", HEX),	// NDEF Key A
58 ];
59 
60 
61 
62 /**
63  * Calculate CRC-8 checksum
64  *
65  * Based on code from nfc-tools.
66  *
67  * @param {ByteString} data the data to calculate the checksum for
68  * @type Number
69  * @return the crc checksum
70  */
71 Mifare.crc8 = function(data) {
72 	var polynom = 0x1d;		// x8 + x4 + x3 + x2 + 1 = 110001101
73 	var crc = 0xC7;			// start value 0xE3 mirrored is 0xC7
74 	
75 	for (var i = 0; i < data.length; i++) {
76 		crc ^= data.byteAt(i);
77 		for (var b = 0; b < 8; b++) {
78 			var msb = crc & 0x80;
79 			crc = (crc << 1) & 0xFF;
80 			if (msb) {
81 				crc ^= polynom;
82 			}
83 		}
84 	}
85 	return crc;
86 }
87 
88 // var ref = new ByteString("01010801080108000000000000040003100310021002100000000000001130", HEX);
89 // assert(ref.length = 31);
90 // assert(Mifare.crc8(ref) == 0x89);
91 
92 
93 
94 /**
95  * Read UID using Get Data command as defined in PCSC Part 3, chapter 3.2.2.1.3
96  *
97  * <p>FEIG readers require Le='04' to automatically switch to Mifare if the card supports both T=CL and Mifare.</p>
98  * 
99  * @type ByteString
100  * @return the 4 byte UID
101  */
102 Mifare.prototype.getUID = function() {
103 	return this.card.sendApdu(0xFF, 0xCA, 0x00, 0x00, 4, [0x9000]);
104 }
105 
106 
107 
108 /**
109  * Load key value into reader using Load Key command as defined in PCSC Part 3, chapter 3.2.2.1.4
110  *
111  * <p>The ACR 122U contactless reader supports key ids 0x00 and 0x01</p>
112  *
113  * <p>The Omnikey cardman 5321 reader supports key ids 0x00 to 0x1F</p>
114  * 
115  * <p>The ACR 122U contactless reader supports key ids 0x00 and 0x01</p>
116  *
117  * <p>The method supports the SCM SDI010 contactless reader which uses a proprietary LOAD KEY APDU with
118  *    preset key identifier 0x60 and 0x61. This command is activated if keyid is 0x60 or 0x61.</p>
119  * 
120  * @param {Number} keyid the key identifier under which the key should be refered to in the reader
121  * @param {ByteString} key the 6 byte key value
122  */
123 Mifare.prototype.loadKey = function(keyid, key) {
124 	assert(typeof(keyid) == "number");
125 	assert(key.length == 6);
126 	
127 	if ((keyid == 0x60) || (keyid == 0x61)) {
128 		this.card.sendApdu(0xFF, 0x82, 0x00, keyid, key, [0x9000]);		// Load key command for SDI010
129 	} else {
130 		this.card.sendApdu(0xFF, 0x82, 0x20, keyid, key, [0x9000]);
131 	}
132 }
133 
134 
135 
136 /**
137  * Read a block using the Read Binary command as defined in PCSC Part 3, chapter 3.2.2.1.8
138  *
139  * @param {Number} block the block to read, starting at 0 for the first block in the first sector.
140  * @type ByteString
141  * @return the 16 byte block content read from the card
142  */
143 Mifare.prototype.readBlock = function(block) {
144 	return this.card.sendApdu(0xFF, 0xB0, block >> 8, block & 0xFF, 16, [0x9000]);
145 }
146 
147 
148 
149 /**
150  * Update a block using the Update Binary command as defined in PCSC Part 3, chapter 3.2.2.1.9
151  *
152  * @param {Number} block the block to read, starting at 0 for the first block in the first sector.
153  * @param {ByteString} data the 16 bytes of the data block to write
154  */
155 Mifare.prototype.updateBlock = function(block, data) {
156 	assert(data.length == 16);
157 	return this.card.sendApdu(0xFF, 0xD6, block >> 8, block & 0xFF, data, [0x9000]);
158 }
159 
160 
161 
162 /**
163  * Perform authentication procedure using General Authenticate command as defined in PCSC Part 3, chapter 3.2.2.1.6
164  *
165  * @param {Number} block the block to authenticate against
166  * @param {Number} keytype must be either Mifare.KEY_A or Mifare.KEY_B
167  * @param {Number} keyid the key id of the key in the reader
168  * @type boolean
169  * @return true if authentication successfull
170  */
171 Mifare.prototype.authenticate = function(block, keytype, keyid) {
172 	var bb = new ByteBuffer();
173 	bb.append(0x01);							// Version
174 	bb.append(ByteString.valueOf(block, 2));
175 	bb.append(keytype);
176 	if ((keyid != 0x60) && (keyid != 0x61)) {
177 		bb.append(keyid);
178 	} else {
179 		bb.append(0x01);		// Support for SCM SDI 010
180 	}
181 	this.card.sendApdu(0xFF,0x86,0x00,0x00, bb.toByteString());
182 	
183 	return this.card.SW == 0x9000;
184 }
185 
186 
187 
188 /**
189  * Create a sector object bound to the current Mifare instance
190  *
191  * @param {Number} no the sector number
192  */
193 Mifare.prototype.newSector = function(no) {
194 	return new Sector(this, no);
195 }
196 
197 
198 
199 /**
200  * Create an object representing an on card sector. Do not call directly but use Mifare.prototype.newSector() instead.
201  *
202  * @class Class representing a sector on a Mifare card
203  * @constructor
204  * @param {Mifare} mifare the card
205  * @param {Number} no the sector number
206  */
207 function Sector(mifare, no) {
208 	this.mifare = mifare;
209 	this.no = no;
210 	this.blocks = [];
211 	this.keyid = [0, 1];
212 }
213 
214 
215 Sector.MASK = [ 0x00E0EE, 0x00D0DD, 0x00B0BB, 0x007077 ];
216 
217 Sector.AC_TRAILER = [
218 	"000 - Key A: Write Key A | AC: Write Never | Key B: Read Key A / Write Key A",		// 000
219 	"001 - Key A: Write Key A | AC: Write Key A | Key B: Read Key A / Write Key A",		// 001
220 	"010 - Key A: Write Never | AC: Write Never | Key B: Read Key A / Write Never",		// 010
221 	"011 - Key A: Write Key B | AC: Write Key B | Key B: Read Never / Write Key B",		// 011
222 	"100 - Key A: Write Key B | AC: Write Never | Key B: Read Never / Write Key B",		// 100
223 	"101 - Key A: Write Never | AC: Write Key B | Key B: Read Never / Write Never",		// 101
224 	"110 - Key A: Write Never | AC: Write Never | Key B: Read Never / Write Never",		// 110
225 	"111 - Key A: Write Never | AC: Write Never | Key B: Read Never / Write Never",		// 111
226 	];
227 
228 // Key A is never readable
229 // Access Conditions are always readable with Key A or Key AB if Key B is used for writing
230 
231 Sector.AC_FIXED_AC_NOKEY_B = 0;
232 Sector.AC_UPDATE_AC_NOKEY_B = 1;		// Transport configuration
233 Sector.AC_READONLY_NOKEY_B = 2;
234 Sector.AC_UPDATE_WITH_KEYB = 3;
235 Sector.AC_FIXED_AC_UPDATE_WITH_KEYB = 4;
236 Sector.AC_UPDATE_AC_FIXED_KEYS = 5;
237 Sector.AC_NEVER2 = 6;
238 
239 Sector.AC_DATA = [
240 	"000 - Read: Key AB | Write: Key AB | Inc: Key AB | Dec: Key AB",		// 000
241 	"001 - Read: Key AB | Write: Never  | Inc: Never  | Dec: Key AB",		// 001
242 	"010 - Read: Key AB | Write: Never  | Inc: Never  | Dec: Never ",		// 010
243 	"011 - Read: Key B  | Write: Key B  | Inc: Never  | Dec: Never ",		// 011
244 	"100 - Read: Key AB | Write: Key B  | Inc: Never  | Dec: Never ",		// 100
245 	"101 - Read: Key B  | Write: Never  | Inc: Never  | Dec: Never ",		// 101
246 	"110 - Read: Key AB | Write: Key B  | Inc: Key B  | Dec: Key AB",		// 110
247 	"111 - Read: Never  | Write: Never  | Inc: Never  | Dec: Never ",		// 111
248 	];
249 
250 Sector.AC_ALWAYS = 0;					// All conditions with Key A or Key B - Transport configuration
251 Sector.AC_NONRECHARGEABLE = 1;			// Only decrement on read only application
252 Sector.AC_READONLY = 2;					// Read only application
253 Sector.AC_KEYBONLY = 3;					// Only using Key B
254 Sector.AC_UPDATEKEYB = 4;				// Use Key B to update
255 Sector.AC_KEYBREADONLY = 5;				// Read only application with only Key B
256 Sector.AC_RECHARGEABLE = 6;				// Rechargable counter
257 Sector.AC_NEVER  = 7;					// No access at all
258 
259 
260 
261 /**
262  * Overwrite internal key id
263  * @param {Number} keyId the key id for the Mifare key
264  * @param {Number} keytype either Mifare.KEY_A (Default) or Mifare.KEY_B.
265  */
266 Sector.prototype.setKeyId = function(keyid, keytype) {
267 	if (typeof(keytype) == "undefined") {
268 		keytype = Mifare.KEY_A;
269 	}
270 	this.keyid[keytype - Mifare.KEY_A] = keyid;
271 }
272 
273 
274 
275 /**
276  * Read a block within the sector
277  *
278  * @param {Number} block the block number between 0 and 3
279  * @type ByteString
280  * @return the data read from the block
281  */
282 Sector.prototype.read = function(block) {
283 	assert(block >= 0);
284 	assert(block <= 3);
285 	var blockoffs = (this.no << 2) + block;
286 	this.blocks[block] = this.mifare.readBlock(blockoffs);
287 	return this.blocks[block];
288 }
289 
290 
291 
292 /**
293  * Update a block within the sector
294  *
295  * @param {Number} block the block number between 0 and 3
296  * @param {ByteString} data the data to write (Optional for sector trailer)
297  */
298 Sector.prototype.update = function(block, data) {
299 	if (typeof(data) == "undefined") {
300 		data = this.blocks[block];
301 	} else {
302 		this.blocks[block] = data
303 	}
304 	var blockoffs = (this.no << 2) + block;
305 	this.mifare.updateBlock(blockoffs, data);
306 }
307 
308 
309 
310 /**
311  * Authenticate against block
312  * <p>Uses the internal key id for this sector for key A and the internal key id + 1 for key B.</p>
313  * @param {Number} block the block number between 0 and 3
314  * @param {Number} keytype must be either Mifare.KEY_A or Mifare.KEY_B
315  * @type boolean
316  * @return true if authentication successfull
317  */
318 Sector.prototype.authenticate = function(block, keytype) {
319 	return this.mifare.authenticate((this.no << 2) + block, keytype, this.keyid[keytype - Mifare.KEY_A]);
320 }
321 
322 
323 
324 /**
325  * Authenticate against block using list from public key table
326  *
327  * @param {Number} block the block number between 0 and 3
328  * @param {Number} keytype must be either Mifare.KEY_A or Mifare.KEY_B
329  * @type Number
330  * @return The key index in Mifare.PUBLICKEYS or -1 if not authenticated
331  */
332 Sector.prototype.authenticatePublic = function(block, keytype) {
333 	var i = 0;
334 	var authenticated = false;
335 
336 	for (var i = 0; i < Mifare.PUBLICKEYS.length; i++) {
337 		this.mifare.loadKey(this.keyid[keytype - Mifare.KEY_A], Mifare.PUBLICKEYS[i]);
338 		if (this.authenticate(block, keytype)) {
339 			return i;
340 		}
341 	}
342 	return -1;
343 }
344 
345 
346 
347 /**
348  * Read all blocks from a sector
349  *
350  * @param {Number} keytype key type to use for authentication (Mifare.KEY_A or Mifare.KEY_B. Defaults to key B.
351  */
352 Sector.prototype.readAll = function(keytype) {
353 	if (typeof(keytype) == "undefined") {
354 		keytype = Mifare.KEY_A;
355 	}
356 	var bb = new ByteBuffer();
357 	this.authenticate(0, keytype);
358 	for (var i = 0; i < 4; i++) {
359 		bb.append(this.read(i));
360 	}
361 	return bb.toByteString();
362 }
363 
364 
365 
366 /**
367  * Return access conditions for a block within the sector
368  *
369  * @param {Number} block the block number between 0 and 3
370  * @type Number
371  * @return one of the Sector.AC_ constants
372  */
373 Sector.prototype.getACforBlock = function(block) {
374 	var c = this.blocks[3].bytes(6, 3).toUnsigned();
375 	return ((((c >> (12 + block)) & 0x01) << 2) +
376 			(((c >> ( 0 + block)) & 0x01) << 1) +
377 			((c >> (4  + block)) & 0x01));
378 }
379 
380 
381 
382 /**
383  * Set the access condition for a block within the sector
384  *
385  * @param {Number} block the block number between 0 and 3
386  * @param {Number} ac one of the Sector.AC_ constants
387  */
388 Sector.prototype.setACforBlock = function(block, ac) {
389 	var c = this.blocks[3].bytes(6, 3).toUnsigned();
390 	c &= Sector.MASK[block];
391 	
392 	c |= ((((ac >> 2) & 0x01) << (12 + block)) +
393 		  (((ac >> 1) & 0x01) << ( 0 + block)) +
394 		  (( ac       & 0x01) << ( 4 + block)));
395 
396 	c |= (((~c &    0xF) << 20) +
397 		  ((~c &   0xF0) <<  4) +
398 		  ((~c & 0xF000) <<  4));
399 
400 	var d = this.blocks[3];
401 	this.blocks[3] = d.bytes(0, 6).concat(ByteString.valueOf(c, 3).concat(d.bytes(9)));
402 }
403 
404 
405 
406 /**
407  * Set the value for Key A
408  *
409  * @param {ByteString} key the key value (6 bytes)
410  */
411 Sector.prototype.setKeyA = function(key) {
412 	var d = this.blocks[3];
413 	this.blocks[3] = key.concat(d.bytes(6));
414 }
415 
416 
417 
418 /**
419  * Set the value for Key B
420  *
421  * @param {ByteString} key the key value (6 bytes)
422  */
423 Sector.prototype.setKeyB = function(key) {
424 	var d = this.blocks[3];
425 	this.blocks[3] = d.bytes(0, 10).concat(key);
426 }
427 
428 
429 
430 /**
431  * Set the data byte in the sector trailer
432  *
433  * @param {ByteString} db the data byte (1 bytes)
434  */
435 Sector.prototype.setHeaderDataByte = function(db) {
436 	var d = this.blocks[3];
437 	this.blocks[3] = d.bytes(0, 9).concat(db).concat(d.bytes(10));
438 }
439 
440 
441 
442 /**
443  * Convert binary data to ASCII code if within the range 0x20 to 0x7E
444  *
445  * @param {ByteString} data the input data
446  * @type String
447  * @return the ASCII string
448  */
449 Sector.toASCII = function(data) {
450 	var str = "";
451 	for (var i = 0; i < data.length; i++) {
452 		var c = data.byteAt(i);
453 		if ((c >= 0x20) && (c < 0x7F)) {
454 			str += String.fromCharCode(c);
455 		} else {
456 			str += ".";
457 		}
458 	}
459 	return str;
460 }
461 
462 
463 
464 /**
465  * Return a human readable presentation of the sector
466  */
467 Sector.prototype.toString = function() {
468 	var str = "";
469 	for (var i = 0; i < 4; i++) {
470 		str += "Sec" + this.no + " Blk" + i + " - ";
471 		
472 		var ac = this.getACforBlock(i);
473 		if (i == 3) {
474 			str += Sector.AC_TRAILER[ac];
475 		} else {
476 			str += Sector.AC_DATA[ac];
477 		}
478 		
479 		str += "\n";
480 
481 		if (typeof(this.blocks[i]) != "undefined") {
482 			str += "  " + this.blocks[i].toString(HEX) + "  " + Sector.toASCII(this.blocks[i]) + "\n";
483 		}
484 	}
485 	return str;
486 }
487 