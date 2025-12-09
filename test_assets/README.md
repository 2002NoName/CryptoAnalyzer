# Test Assets

Ten katalog zawiera przykładowe obrazy dysków używane w testach integracyjnych.

**Uwaga:** pliki nie są synchronizowane z repozytorium (katalog umieszczono w `.gitignore`).

## Generowanie próbek testowych

### Prosty obraz RAW z FAT32

```bash
dd if=/dev/zero of=test_fat32.img bs=1M count=16
mkfs.vfat test_fat32.img
```

### Symulacja nagłówka BitLocker

```python
with open("test_bitlocker.img", "wb") as f:
    f.write(b"\x00" * 512)
    f.write(b"-FVE-FS-")
    f.write(b"\x00" * (4096 - 520))
```

### Symulacja LUKS

```python
with open("test_luks.img", "wb") as f:
    f.write(bytes.fromhex("4C554B53BABE"))
    f.write((2).to_bytes(2, "little"))
    f.write(b"\x00" * 1024)
```

Wszystkie obrazy testowe powinny znajdować się w tym katalogu jako pliki `.img`.
