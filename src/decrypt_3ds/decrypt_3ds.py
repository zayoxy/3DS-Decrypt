import struct
import sys

from Crypto.Cipher import AES
from Crypto.Util import Counter

rol = lambda val, r_bits, max_bits: (
    (val << r_bits % max_bits) & (2**max_bits - 1)
    | ((val & (2**max_bits - 1)) >> (max_bits - (r_bits % max_bits)))
)


def to_bytes(num):
    result = []
    tmp = num
    while len(result) < 16:
        result.append(tmp & 0xFF)
        tmp >>= 8
    return bytes(result[::-1])


# Setup Keys and IVs
plain_counter = struct.unpack(">Q", b"\x01\x00\x00\x00\x00\x00\x00\x00")
exefs_counter = struct.unpack(">Q", b"\x02\x00\x00\x00\x00\x00\x00\x00")
romfs_counter = struct.unpack(">Q", b"\x03\x00\x00\x00\x00\x00\x00\x00")
Constant = struct.unpack(
    ">QQ", b"\x1f\xf9\xe9\xaa\xc5\xfe\x04\x08\x02\x45\x91\xdc\x5d\x52\x76\x8a"
)

# Retail keys
KeyX0x18 = struct.unpack(
    ">QQ", b"\x82\xe9\xc9\xbe\xbf\xb8\xbd\xb8\x75\xec\xc0\xa0\x7d\x47\x43\x74"
)
KeyX0x1B = struct.unpack(
    ">QQ", b"\x45\xad\x04\x95\x39\x92\xc7\xc8\x93\x72\x4a\x9a\x7b\xce\x61\x82"
)
KeyX0x25 = struct.unpack(
    ">QQ", b"\xce\xe7\xd8\xab\x30\xc0\x0d\xae\x85\x0e\xf5\xe3\x82\xac\x5a\xf3"
)
KeyX0x2C = struct.unpack(
    ">QQ", b"\xb9\x8e\x95\xce\xca\x3e\x4d\x17\x1f\x76\xa9\x4d\xe9\x34\xc0\x53"
)

# Dev Keys: (Uncomment if your ROM uses dev keys)
# KeyX0x18 = struct.unpack('>QQ', b'\x30\x4B\xF1\x46\x83\x72\xEE\x64\x11\x5E\xBD\x40\x93\xD8\x42\x76')
# KeyX0x1B = struct.unpack('>QQ', b'\x6C\x8B\x29\x44\xA0\x72\x60\x35\xF9\x41\xDF\xC0\x18\x52\x4F\xB6')
# KeyX0x25 = struct.unpack('>QQ', b'\x81\x90\x7A\x4B\x6F\x1B\x47\x32\x3A\x67\x79\x74\xCE\x4A\xD7\x1B')
# KeyX0x2C = struct.unpack('>QQ', b'\x51\x02\x07\x51\x55\x07\xCB\xB1\x8E\x24\x3D\xCB\x85\xE2\x3A\x1D')


def decrypt(path):
    with open(path, "rb") as f, open(path, "rb+") as g:
        print(path)
        f.seek(0x100)
        magic = f.read(0x04)
        if magic == b"NCSD":
            f.seek(0x188)
            ncsd_flags = struct.unpack("<BBBBBBBB", f.read(0x8))
            sectorsize = 0x200 * (2 ** ncsd_flags[6])

            for p in range(8):
                f.seek((0x120) + (p * 0x08))
                part_off = struct.unpack("<L", f.read(0x04))
                part_len = struct.unpack("<L", f.read(0x04))

                f.seek((part_off[0] * sectorsize) + 0x188)
                raw = f.read(0x8)
                if len(raw) < 8:
                    print("Partition %1d Not found... Skipping..." % p)
                    continue
                partition_flags = struct.unpack("<BBBBBBBB", raw)

                if partition_flags[7] & 0x04:
                    print("Partition %1d: Already Decrypted?..." % p)
                else:
                    if (part_off[0] * sectorsize) > 0:
                        f.seek((part_off[0] * sectorsize) + 0x100)
                        magic = f.read(0x04)

                        if magic == b"NCCH":
                            f.seek((part_off[0] * sectorsize) + 0x0)
                            part_keyy = struct.unpack(">QQ", f.read(0x10))

                            f.seek((part_off[0] * sectorsize) + 0x108)
                            tid = struct.unpack("<Q", f.read(0x8))
                            plain_iv = tid[::] + plain_counter[::]
                            exefs_iv = tid[::] + exefs_counter[::]
                            romfs_iv = tid[::] + romfs_counter[::]

                            f.seek((part_off[0] * sectorsize) + 0x160)
                            exhdr_sbhash = "%016X%016X%016X%016X" % struct.unpack(
                                ">QQQQ", f.read(0x20)
                            )

                            f.seek((part_off[0] * sectorsize) + 0x180)
                            exhdr_len = struct.unpack("<L", f.read(0x04))

                            f.seek((part_off[0] * sectorsize) + 0x190)
                            plain_off = struct.unpack("<L", f.read(0x04))
                            plain_len = struct.unpack("<L", f.read(0x04))

                            f.seek((part_off[0] * sectorsize) + 0x198)
                            logo_off = struct.unpack("<L", f.read(0x04))
                            logo_len = struct.unpack("<L", f.read(0x04))

                            f.seek((part_off[0] * sectorsize) + 0x1A0)
                            exefs_off = struct.unpack("<L", f.read(0x04))
                            exefs_len = struct.unpack("<L", f.read(0x04))

                            f.seek((part_off[0] * sectorsize) + 0x1B0)
                            romfs_off = struct.unpack("<L", f.read(0x04))
                            romfs_len = struct.unpack("<L", f.read(0x04))

                            f.seek((part_off[0] * sectorsize) + 0x1C0)
                            exefs_sbhash = "%016X%016X%016X%016X" % struct.unpack(
                                ">QQQQ", f.read(0x20)
                            )

                            f.seek((part_off[0] * sectorsize) + 0x1E0)
                            romfs_sbhash = "%016X%016X%016X%016X" % struct.unpack(
                                ">QQQQ", f.read(0x20)
                            )

                            plainIV = int("%016X%016X" % plain_iv, 16)
                            exefsIV = int("%016X%016X" % exefs_iv, 16)
                            romfsIV = int("%016X%016X" % romfs_iv, 16)
                            KeyY = int("%016X%016X" % part_keyy, 16)
                            Const = int("%016X%016X" % Constant, 16)

                            KeyX2C = int("%016X%016X" % KeyX0x2C, 16)
                            NormalKey2C = rol((rol(KeyX2C, 2, 128) ^ KeyY) + Const, 87, 128)

                            if partition_flags[7] & 0x01:
                                NormalKey = 0x00
                                NormalKey2C = 0x00
                                if p == 0:
                                    print("Encryption Method: Zero Key")
                            else:
                                if partition_flags[3] == 0x00:
                                    KeyX = int("%016X%016X" % KeyX0x2C, 16)
                                    if p == 0:
                                        print("Encryption Method: Key 0x2C")
                                elif partition_flags[3] == 0x01:
                                    KeyX = int("%016X%016X" % KeyX0x25, 16)
                                    if p == 0:
                                        print("Encryption Method: Key 0x25")
                                elif partition_flags[3] == 0x0A:
                                    KeyX = int("%016X%016X" % KeyX0x18, 16)
                                    if p == 0:
                                        print("Encryption Method: Key 0x18")
                                elif partition_flags[3] == 0x0B:
                                    KeyX = int("%016X%016X" % KeyX0x1B, 16)
                                    if p == 0:
                                        print("Encryption Method: Key 0x1B")
                                NormalKey = rol((rol(KeyX, 2, 128) ^ KeyY) + Const, 87, 128)

                            if exhdr_len[0] > 0:
                                f.seek((part_off[0] + 1) * sectorsize)
                                g.seek((part_off[0] + 1) * sectorsize)
                                exefsctr2C = Counter.new(128, initial_value=plainIV)
                                exefsctrmode2C = AES.new(
                                    to_bytes(NormalKey2C),
                                    AES.MODE_CTR,
                                    counter=exefsctr2C,
                                )
                                print("Partition %1d ExeFS: Decrypting: ExHeader" % p)
                                g.write(exefsctrmode2C.decrypt(f.read(0x800)))

                            if exefs_len[0] > 0:
                                f.seek((part_off[0] + exefs_off[0]) * sectorsize)
                                g.seek((part_off[0] + exefs_off[0]) * sectorsize)
                                exefsctr2C = Counter.new(128, initial_value=exefsIV)
                                exefsctrmode2C = AES.new(
                                    to_bytes(NormalKey2C),
                                    AES.MODE_CTR,
                                    counter=exefsctr2C,
                                )
                                g.write(exefsctrmode2C.decrypt(f.read(sectorsize)))
                                print(
                                    "Partition %1d ExeFS: Decrypting: ExeFS Filename Table"
                                    % p
                                )

                                if partition_flags[3] in (0x01, 0x0A, 0x0B):
                                    code_filelen = 0
                                    for j in range(10):
                                        f.seek(
                                            ((part_off[0] + exefs_off[0]) * sectorsize)
                                            + j * 0x10
                                        )
                                        g.seek(
                                            ((part_off[0] + exefs_off[0]) * sectorsize)
                                            + j * 0x10
                                        )
                                        exefs_filename = struct.unpack("<8s", g.read(0x08))
                                        fname = exefs_filename[0].rstrip(b"\x00")
                                        if fname == b".code":
                                            code_fileoff = struct.unpack("<L", g.read(0x04))
                                            code_filelen = struct.unpack("<L", g.read(0x04))
                                            datalenM = code_filelen[0] // (1024 * 1024)
                                            datalenB = code_filelen[0] % (1024 * 1024)
                                            ctroffset = (
                                                code_fileoff[0] + sectorsize
                                            ) // 0x10
                                            exefsctr = Counter.new(
                                                128, initial_value=exefsIV + ctroffset
                                            )
                                            exefsctr2C = Counter.new(
                                                128, initial_value=exefsIV + ctroffset
                                            )
                                            exefsctrmode = AES.new(
                                                to_bytes(NormalKey),
                                                AES.MODE_CTR,
                                                counter=exefsctr,
                                            )
                                            exefsctrmode2C = AES.new(
                                                to_bytes(NormalKey2C),
                                                AES.MODE_CTR,
                                                counter=exefsctr2C,
                                            )
                                            f.seek(
                                                (
                                                    (part_off[0] + exefs_off[0] + 1)
                                                    * sectorsize
                                                )
                                                + code_fileoff[0]
                                            )
                                            g.seek(
                                                (
                                                    (part_off[0] + exefs_off[0] + 1)
                                                    * sectorsize
                                                )
                                                + code_fileoff[0]
                                            )
                                            for i in range(datalenM):
                                                g.write(
                                                    exefsctrmode2C.encrypt(
                                                        exefsctrmode.decrypt(
                                                            f.read(1024 * 1024)
                                                        )
                                                    )
                                                )
                                                print(
                                                    "\rPartition %1d ExeFS: Decrypting: .code... %4d / %4d mb..."
                                                    % (p, i, datalenM + 1),
                                                    end="",
                                                )
                                            if datalenB > 0:
                                                g.write(
                                                    exefsctrmode2C.encrypt(
                                                        exefsctrmode.decrypt(
                                                            f.read(datalenB)
                                                        )
                                                    )
                                                )
                                            print(
                                                "\rPartition %1d ExeFS: Decrypting: .code... %4d / %4d mb... Done!"
                                                % (p, datalenM + 1, datalenM + 1)
                                            )

                                exefsSizeM = ((exefs_len[0] - 1) * sectorsize) // (
                                    1024 * 1024
                                )
                                exefsSizeB = ((exefs_len[0] - 1) * sectorsize) % (
                                    1024 * 1024
                                )
                                ctroffset = sectorsize // 0x10
                                exefsctr2C = Counter.new(
                                    128, initial_value=exefsIV + ctroffset
                                )
                                exefsctrmode2C = AES.new(
                                    to_bytes(NormalKey2C),
                                    AES.MODE_CTR,
                                    counter=exefsctr2C,
                                )
                                f.seek((part_off[0] + exefs_off[0] + 1) * sectorsize)
                                g.seek((part_off[0] + exefs_off[0] + 1) * sectorsize)
                                for i in range(exefsSizeM):
                                    g.write(exefsctrmode2C.decrypt(f.read(1024 * 1024)))
                                    print(
                                        "\rPartition %1d ExeFS: Decrypting: %4d / %4d mb"
                                        % (p, i, exefsSizeM + 1),
                                        end="",
                                    )
                                if exefsSizeB > 0:
                                    g.write(exefsctrmode2C.decrypt(f.read(exefsSizeB)))
                                print(
                                    "\rPartition %1d ExeFS: Decrypting: %4d / %4d mb... Done"
                                    % (p, exefsSizeM + 1, exefsSizeM + 1)
                                )

                            else:
                                print("Partition %1d ExeFS: No Data... Skipping..." % p)

                            if romfs_off[0] != 0:
                                romfsBlockSize = 16
                                romfsSizeM = (romfs_len[0] * sectorsize) // (
                                    romfsBlockSize * 1024 * 1024
                                )
                                romfsSizeB = (romfs_len[0] * sectorsize) % (
                                    romfsBlockSize * 1024 * 1024
                                )
                                romfsSizeTotalMb = (romfs_len[0] * sectorsize) // (
                                    1024 * 1024
                                ) + 1

                                romfsctr = Counter.new(128, initial_value=romfsIV)
                                romfsctrmode = AES.new(
                                    to_bytes(NormalKey), AES.MODE_CTR, counter=romfsctr
                                )

                                f.seek((part_off[0] + romfs_off[0]) * sectorsize)
                                g.seek((part_off[0] + romfs_off[0]) * sectorsize)
                                for i in range(romfsSizeM):
                                    g.write(
                                        romfsctrmode.decrypt(
                                            f.read(romfsBlockSize * 1024 * 1024)
                                        )
                                    )
                                    print(
                                        "\rPartition %1d RomFS: Decrypting: %4d / %4d mb"
                                        % (p, i * romfsBlockSize, romfsSizeTotalMb),
                                        end="",
                                    )
                                if romfsSizeB > 0:
                                    g.write(romfsctrmode.decrypt(f.read(romfsSizeB)))
                                print(
                                    "\rPartition %1d RomFS: Decrypting: %4d / %4d mb... Done"
                                    % (p, romfsSizeTotalMb, romfsSizeTotalMb)
                                )

                            else:
                                print("Partition %1d RomFS: No Data... Skipping..." % p)

                            g.seek((part_off[0] * sectorsize) + 0x18B)
                            g.write(struct.pack("<B", 0x00))
                            g.seek((part_off[0] * sectorsize) + 0x18F)
                            flag = int(partition_flags[7])
                            flag = flag & ((0x01 | 0x20) ^ 0xFF)
                            flag = flag | 0x04
                            g.write(struct.pack("<B", flag))

                        else:
                            print("Partition %1d Unable to read NCCH header" % p)
                    else:
                        print("Partition %1d Not found... Skipping..." % p)
            print("Done...")
        else:
            print("Error: Not a 3DS Rom?")


if __name__ == "__main__":
    decrypt(sys.argv[1])