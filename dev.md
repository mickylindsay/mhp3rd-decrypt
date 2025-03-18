Played through the fan translation of Japan exclusive Monster Hunter Portable 3rd. Was curious how the fan translation worked and the lead me through rabbit holes, old internet, and a ton of dead ends so far

Feb 2, 2025
RetroAchievements hosts the fan translation on their github repo - https://github.com/RetroAchievements/RAPatches/blob/main/PlayStation%20Portable/Translation/English/17976-MonsterHunterPortable3rd-English.zip
Just an xdelta patch to apply to the Japanese ISO

Feb 18, 2025
Mounted the psp iso and has userdata/data.bin about a gigabyte
Dropped that into umdgen and it stays the iso isn't compressed
Scrubbed through data.bin with MadEdit and even swapping into unicode encoding, no obvious strings to pull either from base ISO or patched one. Definitely encrypted.

Tried a ram dump in ppsspp but not sure how to translate any of that into decrypting the data.

Found a toolkit for translating the Bakemonogatari PSP game, but will only be useful after decryption and only if PSP data/structure is pretty standard.

14 year only reddit post linking the mysterious "Nimer's Toolkit" and recruiting for a Portable 3rd translation project
https://www.reddit.com/r/MonsterHunter/comments/eyaz0/who_wants_to_help_me_translate_monster_hunter/
Dead links and nothing I can dig from internet archives. Not finding anything concrete around "Nimer"

PPSSPP can export the decrypted boot ELF. Installing ghidra to go over it and see if I can pull the DATA.BIN decryption asm out of it

There is a whole Ghidra x PSP plugin set and tooling https://github.com/kotcrab/ghidra-allegrex
Provides some system call function labels to the decomp. Guess these got pulled out of some PSP ISOs that are unencrypted and still have symbols?

Full on Reversing guide https://psp-re.github.io/quickstart/

Spent like an hour working through some functions and adding labels that basically just ended up being some strlen wrappers, and the entry point that spawns the larger thread.
Nothing jumping out at me searching up just raw XOR instructions.

2016 ZenHax forumn post gave some details on the encryption
https://www.zenhax.com/viewtopic.php@t=2863.html
and most importantly links to https://github.com/svanheulen/mhef which holds the whole encryption algo for all the PSP monster hunter games.
decoding table lookup, and the XOR encryption key/mod!

No clue how these keys were aquired, but if I knew more about reversing and assembly probably maybe would have been easier to find them in the boot rom?

Slowly working the code through python REPL to make sure I understand how its working.
Starts with decrypting a table of contents.

Every 4 bytes in the ToC is an index for files with 2kb chunks.

first two indexesare 17 and 18 meaning the first "file" starts with 17 2kb chunks then the next file is 2kb starting at pos 17*2048 to pos 18*2048

it feels like im really close. walking through the repl itt only spit out 6k files, not the 8k I expected based on ToC.
Lots of junk data, thnk there is something wrong with how the table of contents lays out files

The first 17 blocks has more then just an increasing set of indexes. The indexes go up for thousands of indexes, but then drops back down to 0x11 before increasing again.

LMAO I was running it on the freedom unite binary data. I found a file with random french and some english game text about pokke village and g-rank diablos.

0x0823c5 is the last thing in the TOC before it drops back down to 0x11
that value * 2048 is 1092495360 which is really close to the size of the binary

the next chunk goes from 0x5d10 to 0x8550

DONE

Its decrypted but there is extra data and large gaps in other places. like a png IEND followed by more data and the next thing in toc is way later

Figured out the encoding table as well. Its just a reshuffling of the decode table
encode_table[decode_table[i]] = i

Got started on reimplementing in rust to make sure I understand how this all works.
But modifying the impl to split all the ToC defined files into their own XX.bin

Mar 18, 2025
Dumped all the .bin files into file to process any usable magic bytes. Updated code to handle the WAV, PNG, and GIF files.

The last ~250 files are all WAVs. Playing one at random and VLC pops open playing recognizable not malformed or corupted monhun sounds brought a level of excitement in writing software that I havn't had in a long time.

Found a resource with tools and a couple "common psp file formats" - https://wiki.vg-resource.com/GMO

Recommends Neosis as a tool to process the two bins that match the GIM file header.

Looking over some other commonly recurring magic bytes in the files I get `.TMH0.14` and `MWo3` on a bunch of files.

MWo3 files appear to be known as `ovl` files internally because after some 4 byte chunks they include strings like "P_m08.ovl"

GTA mod wiki for PS2 games give similar format https://gtamods.com/wiki/PS2_Code_Overlay including the file name strings. Looks like it will be general code dumps with their own text/data segments.

Another repo lists out some magic bytes as files so im locking in tmh and mwo files along with the previous. https://github.com/codestation/mhtools/blob/master/src/crypt/Decrypter.java#L36. This this is just coming from the ascii values rather than any actual file format defintion.

Found 2012 early attempts to emulatate Portable 3rd, that holds some references to the ovl strings I found in headers. - https://www.emunewz.net/forum/showthread.php?tid=103869

Looks like .hack modding also uses this format and ye they are code binaries - https://www.dothack.org/topic/1574-a-starter-guide-to-the-main-executable-file-of-hackinfection/

TMH file searches gave me this about half a page down...
https://github.com/Kurogami2134/MHP3rd-Game-FIle-List pssh somebody already did so much
https://fucomplete.github.io/ oh god there is a whole community already 