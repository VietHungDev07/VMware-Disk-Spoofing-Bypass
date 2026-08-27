// AceSpyDrv.sys — Full disk serial filter for Strinova-SPOOF
// Mapped with KDU (no service). PatchGuard-safe: no inline hooks, no
// MajorFunction hijack. Uses IoAttachDeviceToDeviceStack + completion on
// our own IRP stack location only.
//
// Intercepts every disk identify path:
//   METHOD_BUFFERED (system buffer, safe at any IRQL):
//     - SMART_RCV_DRIVE_DATA              (0x7C088)  CrystalDiskInfo
//     - IOCTL_ATA_PASS_THROUGH            (0x4D02C)  ATA IDENTIFY 0xEC
//     - IOCTL_SCSI_PASS_THROUGH           (0x4D004)  SCSI INQUIRY 0x12
//     - IOCTL_SCSI_PASS_THROUGH_EX        (0x4D018)
//     - IOCTL_SCSI_GET_INQUIRY_DATA       (0x41018)  Legacy bus scan
//     - IOCTL_STORAGE_QUERY_PROPERTY      (0x2D1400) StorageDeviceProperty
//         + StorageDeviceIdProperty       (NVMe controller identify)
//     - IOCTL_STORAGE_PROTOCOL_COMMAND    (0x2D14F0) NVMe Admin Identify
//
//   DIRECT (DataBuffer is user VA — MDL-mapped before patching):
//     - IOCTL_ATA_PASS_THROUGH_DIRECT     (0x4D028)
//     - IOCTL_ATA_PASS_THROUGH_DIRECT_EX  (0x4D030)
//     - IOCTL_SCSI_PASS_THROUGH_DIRECT    (0x4D014)
//     - IOCTL_SCSI_PASS_THROUGH_DIRECT_EX (0x4D01C)
//
//   NVMe vendor pass-through:
//     - NVME_PASS_THROUGH_SRB_IO_CODE     (0xE0000800)
//     - Intel NVMe pass-through           (0xF000A02)
//
// Also zeroes SMART attributes:
//   - ID 9  (Power-On Hours)
//   - ID 12 (Power Cycle Count)
//   - ID 194 (Temperature) — preserved (not unique)
//
// Also spoofs binary identifiers:
//   - WWN (World Wide Name) in ATA IDENTIFY word 84-87 + 108-111
//   - EUI64 / NGUID in NVMe Identify response

#include <ntddk.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <ntddstor.h>
#include <scsi.h>
#include <ata.h>

// DIRECTORY_BASIC_INFORMATION for ZwQueryDirectoryObject
// OBJECT_DIRECTORY_INFORMATION — actual struct returned by ZwQueryDirectoryObject
// Layout: array of these entries (no NextEntryOffset), string data follows array
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

extern "C" {
    extern POBJECT_TYPE* IoDriverObjectType;

    // Not in ntddk.h, declared in ntifs.h
    NTSYSCALLAPI NTSTATUS NTAPI ZwOpenDirectoryObject(
        _Out_ PHANDLE DirectoryHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes);

    NTSYSCALLAPI NTSTATUS NTAPI ZwQueryDirectoryObject(
        _In_ HANDLE DirectoryHandle,
        _Out_writes_bytes_(BufferLength) PVOID Buffer,
        _In_ ULONG BufferLength,
        _In_ BOOLEAN ReturnSingleEntry,
        _In_ BOOLEAN RestartScan,
        _Inout_ PULONG Context,
        _Out_opt_ PULONG ReturnLength);

    NTKERNELAPI NTSTATUS NTAPI ObReferenceObjectByName(
        PUNICODE_STRING ObjectName,
        ULONG Attributes,
        PACCESS_STATE PassedAccessState,
        ACCESS_MASK DesiredAccess,
        POBJECT_TYPE ObjectType,
        KPROCESSOR_MODE AccessMode,
        PVOID ParseContext,
        PVOID* Object);

    NTSYSAPI NTSTATUS NTAPI IoCreateDriver(
        PUNICODE_STRING DriverName,
        PDRIVER_INITIALIZE InitializationFunction);

    NTKERNELAPI NTSTATUS NTAPI IoEnumerateDeviceObjectList(
        PDRIVER_OBJECT DriverObject,
        PDEVICE_OBJECT* DeviceObjectList,
        ULONG DeviceObjectListSize,
        PULONG ActualNumberDeviceObjects);
}

// ============================================================================
// IOCTL codes — only define what WDK headers don't provide
// ============================================================================
#ifndef SMART_RCV_DRIVE_DATA
#define SMART_RCV_DRIVE_DATA            CTL_CODE(IOCTL_DISK_BASE, 0x0022, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif
#ifndef IOCTL_SCSI_GET_INQUIRY_DATA
#define IOCTL_SCSI_GET_INQUIRY_DATA     CTL_CODE(IOCTL_SCSI_BASE, 0x0403, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

// ATA_PASS_THROUGH_DIRECT_EX is not in older WDK headers
#ifndef IOCTL_ATA_PASS_THROUGH_DIRECT_EX
#define IOCTL_ATA_PASS_THROUGH_DIRECT_EX CTL_CODE(IOCTL_SCSI_BASE, 0x040E, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

// ATA_PASS_THROUGH_EX structure (not in all WDK versions)
#ifndef _ATA_PASS_THROUGH_DIRECT_EX_DEFINED
typedef struct _ATA_PASS_THROUGH_DIRECT_EX {
    ULONG Length;
    ULONG DataTransferLength;
    VOID* DataBuffer;
    UCHAR CurrentTaskFile[8];
    UCHAR PreviousTaskFile[8];
    UCHAR DataBufferOffset;
    UCHAR Reserved[3];
} ATA_PASS_THROUGH_DIRECT_EX, *PATA_PASS_THROUGH_DIRECT_EX;
#define _ATA_PASS_THROUGH_DIRECT_EX_DEFINED
#endif

#define NVME_STORPORT_DRIVER            0xE000
#define NVME_PASS_THROUGH_SRB_IO_CODE   CTL_CODE(NVME_STORPORT_DRIVER, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INTEL_NVME_PASS_THROUGH   CTL_CODE(0xF000, 0xA02, METHOD_BUFFERED, FILE_ANY_ACCESS)

// StorageQueryProperty PropertyId values
#define StorageDeviceProperty           0
#define StorageAdapterProperty          1
#define StorageDeviceIdProperty         1

// NVMe protocol command data types
#define NVMeDataTypeUnknown             0
#define NVMeDataTypeIdentify            1
#define NVMeDataTypeLogPage             2

// NVMe Identify CNS values
#define NVMeCnsIdentifyController       1

// ============================================================================
// ATA IDENTIFY offsets
// ============================================================================
#define ATA_IDENTIFY_SERIAL_OFFSET   20
#define ATA_IDENTIFY_SERIAL_LEN      20
#define ATA_IDENTIFY_MODEL_OFFSET    54
#define ATA_IDENTIFY_MODEL_LEN       40
#define ATA_IDENTIFY_FW_OFFSET       46
#define ATA_IDENTIFY_FW_LEN          8
#define ATA_IDENTIFY_WWN_OFFSET      108   // words 108-111 (byte 216)
#define ATA_IDENTIFY_WWN_LEN         8
#define SENDCMDOUTPARAMS_BUFFER_OFFSET  16

// SCSI INQUIRY offsets
#define SCSI_INQUIRY_VENDOR_OFFSET   8
#define SCSI_INQUIRY_VENDOR_LEN      8
#define SCSI_INQUIRY_PRODUCT_OFFSET  16
#define SCSI_INQUIRY_PRODUCT_LEN     16
#define SCSI_INQUIRY_REV_OFFSET      32
#define SCSI_INQUIRY_REV_LEN         4
#define SCSI_INQUIRY_SERIAL_OFFSET   36   // Serial Number page (0x80)
#define SCSI_INQUIRY_SERIAL_LEN      20

// NVMe IDENTIFY controller response offsets
#define NVME_IDENTIFY_SERIAL_OFFSET  4
#define NVME_IDENTIFY_SERIAL_LEN     20
#define NVME_IDENTIFY_MODEL_OFFSET   24
#define NVME_IDENTIFY_MODEL_LEN      40
#define NVME_IDENTIFY_FW_OFFSET      64
#define NVME_IDENTIFY_FW_LEN         8
#define NVME_IDENTIFY_EUI64_OFFSET   72   // IEEE EUI-64 (8 bytes)
#define NVME_IDENTIFY_EUI64_LEN      8

// SMART attribute offsets (within SMART attribute table in IDENTIFY/SMART data)
#define SMART_ATTR_TABLE_OFFSET      2    // offset within SENDCMDOUTPARAMS bBuffer
#define SMART_ATTR_ENTRY_SIZE        12
#define SMART_ATTR_ID_POWER_ON_HOURS 9
#define SMART_ATTR_ID_POWER_CYCLE    12

// STORAGE_DEVICE_DESCRIPTOR offsets (for IOCTL_STORAGE_QUERY_PROPERTY)
#define STORAGE_DESC_SERIAL_OFFSET   36   // SerialNumberOffset is dynamic, but often 36
#define STORAGE_DESC_VENDOR_OFFSET   32   // VendorIdOffset
#define STORAGE_DESC_PRODUCT_OFFSET  28   // ProductIdOffset
#define STORAGE_DESC_REVISION_OFFSET 40   // ProductRevisionOffset

// ============================================================================
// Serial cache
// ============================================================================
#define MAX_DISK_CACHE 8
#define MAX_FILTERS    64
#define ATTACH_DELAY_100NS  (-10LL * 1000 * 1000 * 10)  // 10 seconds

struct DiskSerialCache {
    BOOLEAN     valid;
    CHAR        origSerial[24];
    CHAR        spoofSerial[24];
    INT         serialLen;
};

struct FILTER_EXT {
    PDEVICE_OBJECT lowerDevice;
    PDEVICE_OBJECT targetDevice;
};

// Context for DIRECT IOCTLs — stores MDL-mapped kernel VA of user DataBuffer
struct DirectCtx {
    ULONG ioctlCode;
    PMDL  mdl;
    PVOID mappedSystemVa;
    ULONG dataLen;
    UCHAR cdb0;        // for SCSI: CDB[0] (0x12 = INQUIRY)
    UCHAR ataCommand;  // for ATA: CurrentTaskFile[6] (0xEC = IDENTIFY)
};

// Context for IRP_MJ_READ — track which sector is being read
struct ReadCtx {
    LARGE_INTEGER startingOffset;  // byte offset from partition start
    ULONG readLength;
};

// MBR disk signature offset (4 bytes at offset 0x1B8 in sector 0)
#define MBR_DISK_SIGNATURE_OFFSET  0x1B8
#define MBR_DISK_SIGNATURE_LEN     4

// GPT header is at sector 1 (LBA 1). DiskGUID at offset 56 (16 bytes)
#define GPT_DISK_GUID_OFFSET       56
#define GPT_DISK_GUID_LEN          16

// GPT partition entries start at sector 2. Each entry is 128 bytes.
// Partition type GUID at offset 0, unique partition GUID at offset 16
#define GPT_PART_ENTRY_SIZE        128
#define GPT_PART_UNIQUE_GUID_OFFSET 16
#define GPT_PART_UNIQUE_GUID_LEN   16

static DiskSerialCache g_serialCache[MAX_DISK_CACHE] = {};
static int g_cacheCount = 0;
static KSPIN_LOCK g_cacheLock = {};

static PDRIVER_OBJECT g_driverObject = nullptr;
static PDEVICE_OBJECT g_filters[MAX_FILTERS] = {};
static volatile LONG g_filterCount = 0;
static volatile LONG g_unloading = 0;

// Context for buffered IOCTL completion — stores IOCTL code + PropertyId
struct BufferedCtx {
    ULONG code;
    ULONG propertyId;  // For IOCTL_STORAGE_QUERY_PROPERTY
};

// Minimal SCSI_REQUEST_BLOCK for x64 (offset-based access)
// Used for IRP_MJ_INTERNAL_DEVICE_CONTROL SRB interception
#pragma pack(push, 8)
typedef struct _ACESPY_SRB {
    USHORT Length;                    // +0
    UCHAR  Function;                 // +2  (0x00 = SRB_FUNCTION_EXECUTE_SCSI, 0x0E = STORAGE_REQUEST_BLOCK)
    UCHAR  SrbStatus;                // +3
    UCHAR  ScsiStatus;               // +4
    UCHAR  PathId;                   // +5
    UCHAR  TargetId;                 // +6
    UCHAR  Lun;                      // +7
    UCHAR  OperationCode;            // +8
    UCHAR  SrbFlags;                 // +9
    USHORT DataTransferLength;       // +10
    ULONG  TimeOutValue;             // +12
    PVOID  DataBuffer;               // +16
    PVOID  DataTransferBuffer;       // +24
    ULONG  SenseInfoBufferLength;    // +32
    PVOID  SenseInfoBuffer;          // +40
    PVOID  NextSrb;                  // +48
    PVOID  OriginalRequest;          // +56
    PVOID  SrbExtension;             // +64
    ULONG  InternalStatus;           // +72
    ULONG  Reserved;                 // +76
    UCHAR  Cdb[16];                  // +80
} ACESPY_SRB, *PACESPY_SRB;
#pragma pack(pop)

// SRB function codes
#define ACESPY_SRB_FUNCTION_EXECUTE_SCSI          0x00
#define ACESPY_SRB_FUNCTION_STORAGE_REQUEST_BLOCK 0x0E

// SRB status
#define ACESPY_SRB_STATUS_SUCCESS 0x01

// Context for IRP_MJ_INTERNAL_DEVICE_CONTROL completion
struct InternalCtx {
    PVOID srbPtr;       // Raw SRB pointer (could be SCSI_REQUEST_BLOCK or STORAGE_REQUEST_BLOCK)
    UCHAR srbFunction;  // SRB Function field
    UCHAR cdb0;         // First CDB byte (for legacy SRB)
    ULONG dataLen;      // Data transfer length
    PVOID dataBuf;      // Data buffer pointer
};

// ============================================================================
// Hash + LCG
// ============================================================================
static ULONG HashBytes(const UCHAR* data, int len) {
    ULONG h = 0x811C9DC5;
    for (int i = 0; i < len; i++) { h ^= data[i]; h *= 0x01000193; }
    return h;
}

static ULONG LcgNext(ULONG& state) {
    state = state * 1664525 + 1013904223;
    return state;
}

// ============================================================================
// Serial generation — preserve format style (hex for NVMe, alphanumeric for SATA)
// ============================================================================
static void GenerateSpoofSerial(const CHAR* orig, int origLen, CHAR* out, int outLen) {
    ULONG seed = HashBytes((const UCHAR*)orig, origLen) ^ 0xDEADBEEF;

    // Detect hex-only serial (NVMe style: "0123ABCDEF")
    bool hexOnly = true;
    for (int i = 0; i < origLen; i++) {
        char c = orig[i];
        if (c == ' ' || c == '\0') continue;
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
            hexOnly = false; break;
        }
    }

    if (hexOnly) {
        static const char hex[] = "0123456789ABCDEF";
        for (int i = 0; i < outLen - 1; i++) {
            if (orig[i] == ' ' || orig[i] == '\0') { out[i] = orig[i]; continue; }
            if (i < 2) { out[i] = orig[i]; continue; }  // preserve first 2 chars
            ULONG r = LcgNext(seed);
            out[i] = hex[r % 16];
        }
    } else {
        static const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        int idx = 0;
        if (outLen > 0) out[idx++] = 'S';
        while (idx < outLen - 1) {
            ULONG r = LcgNext(seed);
            out[idx++] = charset[r % (sizeof(charset) - 1)];
        }
    }
    out[outLen - 1] = '\0';
}

static BOOLEAN GetSpoofSerial(const CHAR* orig, int origLen, CHAR* out, int outBufLen) {
    if (!orig || origLen <= 0 || !out || outBufLen <= 0) return FALSE;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_cacheLock, &oldIrql);

    for (int i = 0; i < g_cacheCount; i++) {
        if (g_serialCache[i].valid && g_serialCache[i].serialLen == origLen &&
            RtlEqualMemory(g_serialCache[i].origSerial, orig, origLen)) {
            int copyLen = origLen < outBufLen ? origLen : outBufLen;
            RtlCopyMemory(out, g_serialCache[i].spoofSerial, copyLen);
            KeReleaseSpinLock(&g_cacheLock, oldIrql);
            return TRUE;
        }
    }

    if (g_cacheCount >= MAX_DISK_CACHE) {
        KeReleaseSpinLock(&g_cacheLock, oldIrql);
        return FALSE;
    }

    DiskSerialCache& entry = g_serialCache[g_cacheCount];
    entry.valid = TRUE;
    entry.serialLen = origLen > 23 ? 23 : origLen;
    RtlCopyMemory(entry.origSerial, orig, entry.serialLen);
    entry.origSerial[entry.serialLen] = '\0';
    GenerateSpoofSerial(orig, origLen, entry.spoofSerial, entry.serialLen + 1);

    int copyLen = entry.serialLen < outBufLen ? entry.serialLen : outBufLen;
    RtlCopyMemory(out, entry.spoofSerial, copyLen);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[AceSpyDrv] Serial cached: orig=<%.*s> spoof=<%s>\n",
               entry.serialLen, entry.origSerial, entry.spoofSerial);

    g_cacheCount++;
    KeReleaseSpinLock(&g_cacheLock, oldIrql);
    return TRUE;
}

// ============================================================================
// ATA string swap + patch
// ============================================================================
static void AtaStringSwapPairs(PUCHAR data, int len) {
    for (int i = 0; i + 1 < len; i += 2) {
        UCHAR tmp = data[i]; data[i] = data[i + 1]; data[i + 1] = tmp;
    }
}

static void PatchAtaIdentify(PUCHAR identifyData, ULONG bufLen) {
    if (!identifyData || bufLen < 512) return;

    // --- Serial (offset 20, 20 bytes) ---
    PUCHAR serialPtr = identifyData + ATA_IDENTIFY_SERIAL_OFFSET;
    CHAR unswapped[ATA_IDENTIFY_SERIAL_LEN + 1] = {};
    RtlCopyMemory(unswapped, serialPtr, ATA_IDENTIFY_SERIAL_LEN);
    AtaStringSwapPairs((PUCHAR)unswapped, ATA_IDENTIFY_SERIAL_LEN);

    int realLen = ATA_IDENTIFY_SERIAL_LEN;
    while (realLen > 0 && (unswapped[realLen - 1] == ' ' || unswapped[realLen - 1] == '\0'))
        realLen--;
    if (realLen <= 0) return;

    CHAR origSerial[ATA_IDENTIFY_SERIAL_LEN + 1] = {};
    RtlCopyMemory(origSerial, unswapped, realLen);

    CHAR spoofSerial[ATA_IDENTIFY_SERIAL_LEN + 1] = {};
    if (!GetSpoofSerial(origSerial, realLen, spoofSerial, ATA_IDENTIFY_SERIAL_LEN)) return;

    CHAR paddedSerial[ATA_IDENTIFY_SERIAL_LEN + 1] = {};
    RtlCopyMemory(paddedSerial, spoofSerial, realLen);
    for (int i = realLen; i < ATA_IDENTIFY_SERIAL_LEN; i++) paddedSerial[i] = ' ';
    AtaStringSwapPairs((PUCHAR)paddedSerial, ATA_IDENTIFY_SERIAL_LEN);
    RtlCopyMemory(serialPtr, paddedSerial, ATA_IDENTIFY_SERIAL_LEN);

    // --- Model (offset 54, 40 bytes) ---
    PUCHAR modelPtr = identifyData + ATA_IDENTIFY_MODEL_OFFSET;
    CHAR spoofModel[] = "Samsung SSD 850 PRO 256GB";
    CHAR paddedModel[ATA_IDENTIFY_MODEL_LEN + 1] = {};
    RtlCopyMemory(paddedModel, spoofModel, sizeof(spoofModel) - 1);
    for (int i = sizeof(spoofModel) - 1; i < ATA_IDENTIFY_MODEL_LEN; i++) paddedModel[i] = ' ';
    AtaStringSwapPairs((PUCHAR)paddedModel, ATA_IDENTIFY_MODEL_LEN);
    RtlCopyMemory(modelPtr, paddedModel, ATA_IDENTIFY_MODEL_LEN);

    // --- Firmware (offset 46, 8 bytes) ---
    PUCHAR fwPtr = identifyData + ATA_IDENTIFY_FW_OFFSET;
    CHAR spoofFw[] = "KXF71W1Q";
    CHAR paddedFw[ATA_IDENTIFY_FW_LEN + 1] = {};
    RtlCopyMemory(paddedFw, spoofFw, ATA_IDENTIFY_FW_LEN);
    AtaStringSwapPairs((PUCHAR)paddedFw, ATA_IDENTIFY_FW_LEN);
    RtlCopyMemory(fwPtr, paddedFw, ATA_IDENTIFY_FW_LEN);

    // --- WWN (offset 108, 8 bytes) — zero it ---
    PUCHAR wwnPtr = identifyData + ATA_IDENTIFY_WWN_OFFSET;
    if (MmIsAddressValid(wwnPtr) && MmIsAddressValid(wwnPtr + 7)) {
        ULONG seed = HashBytes(wwnPtr, ATA_IDENTIFY_WWN_LEN) ^ 0xCAFEBABE;
        for (int i = 0; i < ATA_IDENTIFY_WWN_LEN; i++) {
            wwnPtr[i] = (UCHAR)(LcgNext(seed) & 0xFF);
        }
    }
}

// ============================================================================
// SCSI INQUIRY patch
// ============================================================================
static void PatchScsiInquiry(PUCHAR inquiryData, ULONG bufLen) {
    if (!inquiryData || bufLen < 36) return;
    RtlCopyMemory(inquiryData + SCSI_INQUIRY_VENDOR_OFFSET, "Samsung ", SCSI_INQUIRY_VENDOR_LEN);
    RtlCopyMemory(inquiryData + SCSI_INQUIRY_PRODUCT_OFFSET, "SSD 850 PRO 256", SCSI_INQUIRY_PRODUCT_LEN);
    RtlCopyMemory(inquiryData + SCSI_INQUIRY_REV_OFFSET, "1W1Q", SCSI_INQUIRY_REV_LEN);
}

// ============================================================================
// NVMe IDENTIFY controller patch
// ============================================================================
static void PatchNvmeIdentify(PUCHAR identifyData, ULONG bufLen) {
    if (!identifyData || bufLen < 72) return;

    // Serial (offset 4, 20 bytes) — NVMe serial is NOT word-swapped
    PUCHAR serialPtr = identifyData + NVME_IDENTIFY_SERIAL_OFFSET;
    CHAR origSerial[NVME_IDENTIFY_SERIAL_LEN + 1] = {};
    RtlCopyMemory(origSerial, serialPtr, NVME_IDENTIFY_SERIAL_LEN);

    int realLen = NVME_IDENTIFY_SERIAL_LEN;
    while (realLen > 0 && (origSerial[realLen - 1] == ' ' || origSerial[realLen - 1] == '\0'))
        realLen--;
    if (realLen <= 0) return;

    CHAR spoofSerial[NVME_IDENTIFY_SERIAL_LEN + 1] = {};
    if (!GetSpoofSerial(origSerial, realLen, spoofSerial, NVME_IDENTIFY_SERIAL_LEN)) return;

    CHAR padded[NVME_IDENTIFY_SERIAL_LEN + 1] = {};
    RtlCopyMemory(padded, spoofSerial, realLen);
    for (int i = realLen; i < NVME_IDENTIFY_SERIAL_LEN; i++) padded[i] = ' ';
    RtlCopyMemory(serialPtr, padded, NVME_IDENTIFY_SERIAL_LEN);

    // Model (offset 24, 40 bytes)
    if (bufLen >= NVME_IDENTIFY_MODEL_OFFSET + NVME_IDENTIFY_MODEL_LEN) {
        RtlCopyMemory(identifyData + NVME_IDENTIFY_MODEL_OFFSET,
                      "Samsung SSD 970 PRO 512GB              ",
                      NVME_IDENTIFY_MODEL_LEN);
    }

    // Firmware (offset 64, 8 bytes)
    if (bufLen >= NVME_IDENTIFY_FW_OFFSET + NVME_IDENTIFY_FW_LEN) {
        RtlCopyMemory(identifyData + NVME_IDENTIFY_FW_OFFSET, "2B2QEXM7", NVME_IDENTIFY_FW_LEN);
    }

    // EUI64 (offset 72, 8 bytes) — randomize
    if (bufLen >= NVME_IDENTIFY_EUI64_OFFSET + NVME_IDENTIFY_EUI64_LEN) {
        PUCHAR eui = identifyData + NVME_IDENTIFY_EUI64_OFFSET;
        ULONG seed = HashBytes(eui, NVME_IDENTIFY_EUI64_LEN) ^ 0xCAFEBABE;
        for (int i = 0; i < NVME_IDENTIFY_EUI64_LEN; i++)
            eui[i] = (UCHAR)(LcgNext(seed) & 0xFF);
    }
}

// ============================================================================
// SMART attribute zeroing (power-on hours + power cycle count)
// ============================================================================
static void ZeroSmartAttributes(PUCHAR smartData, ULONG bufLen) {
    if (!smartData || bufLen < 362) return;
    // SMART attribute table starts at offset 2, each entry is 12 bytes
    for (int i = 0; i < 30; i++) {
        ULONG off = SMART_ATTR_TABLE_OFFSET + i * SMART_ATTR_ENTRY_SIZE;
        if (off + SMART_ATTR_ENTRY_SIZE > bufLen) break;
        UCHAR attrId = smartData[off];
        if (attrId == 0) break;
        if (attrId == SMART_ATTR_ID_POWER_ON_HOURS || attrId == SMART_ATTR_ID_POWER_CYCLE) {
            RtlZeroMemory(&smartData[off + 5], 6);  // zero raw value (bytes 5-10)
        }
    }
}

// ============================================================================
// STORAGE_DEVICE_DESCRIPTOR patch (IOCTL_STORAGE_QUERY_PROPERTY response)
// ============================================================================
static void PatchStorageDeviceDescriptor(PUCHAR descData, ULONG bufLen) {
    if (!descData || bufLen < 36) return;
    // STORAGE_DEVICE_DESCRIPTOR layout (from ntddstor.h):
    //   ULONG Version              (offset 0)
    //   ULONG Size                 (offset 4)
    //   UCHAR DeviceType           (offset 8)
    //   UCHAR DeviceTypeModifier   (offset 9)
    //   BOOLEAN RemovableMedia     (offset 10)
    //   BOOLEAN CommandQueueing    (offset 11)
    //   ULONG VendorIdOffset       (offset 12)
    //   ULONG ProductIdOffset      (offset 16)
    //   ULONG ProductRevisionOffset(offset 20)
    //   ULONG SerialNumberOffset   (offset 24)
    //   STORAGE_BUS_TYPE BusType   (offset 28)
    //   ULONG RawPropertiesLength  (offset 32)
    //   UCHAR RawDeviceProperties[] (offset 36)

    // Log all offsets for debugging
    ULONG vendorOff = *(ULONG*)(descData + 12);
    ULONG productOff = *(ULONG*)(descData + 16);
    ULONG revOff = *(ULONG*)(descData + 20);
    ULONG serialOff = *(ULONG*)(descData + 24);
    ULONG busType = *(ULONG*)(descData + 28);
    ULONG rawLen = *(ULONG*)(descData + 32);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AceSpyDrv] DESC: vendor=%u product=%u rev=%u serial=%u bus=%u rawLen=%u\n",
             vendorOff, productOff, revOff, serialOff, busType, rawLen);

    // Patch serial number
    if (serialOff > 0 && serialOff < bufLen) {
        PUCHAR serialPtr = descData + serialOff;
        ULONG serialLen = 0;
        while (serialOff + serialLen < bufLen && serialPtr[serialLen] != 0)
            serialLen++;
        if (serialLen > 0 && serialLen <= 40) {
            CHAR origSerial[41] = {};
            RtlCopyMemory(origSerial, serialPtr, serialLen);
            CHAR spoofSerial[41] = {};
            if (GetSpoofSerial(origSerial, (int)serialLen, spoofSerial, 40)) {
                RtlCopyMemory(serialPtr, spoofSerial, serialLen);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[AceSpyDrv] Serial patched (off=%u len=%u): %.*s -> %s\n",
                           serialOff, serialLen, serialLen, origSerial, spoofSerial);
            }
        }
    }

    // Patch VendorId
    if (vendorOff > 0 && vendorOff < bufLen) {
        PUCHAR vendorPtr = descData + vendorOff;
        ULONG vendorLen = 0;
        while (vendorOff + vendorLen < bufLen && vendorPtr[vendorLen] != 0)
            vendorLen++;
        if (vendorLen > 0 && vendorLen <= 16) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AceSpyDrv] VendorId (off=%u len=%u): %.*s\n",
                     vendorOff, vendorLen, vendorLen, vendorPtr);
            RtlCopyMemory(vendorPtr, "Seagate ", vendorLen < 8 ? vendorLen : 8);
        }
    }

    // Patch ProductId
    if (productOff > 0 && productOff < bufLen) {
        PUCHAR productPtr = descData + productOff;
        ULONG productLen = 0;
        while (productOff + productLen < bufLen && productPtr[productLen] != 0)
            productLen++;
        if (productLen > 0 && productLen <= 40) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AceSpyDrv] ProductId (off=%u len=%u): %.*s\n",
                     productOff, productLen, productLen, productPtr);
            const char* spoof = "Seagate SSD 860 QVO  ";  // 21 chars, pad to 24
            ULONG spoofLen = (ULONG)strlen(spoof);
            ULONG copyLen = productLen < spoofLen ? productLen : spoofLen;
            RtlCopyMemory(productPtr, spoof, copyLen);
            // Pad remaining with spaces
            for (ULONG j = copyLen; j < productLen; j++) productPtr[j] = ' ';
        }
    }

    // Patch RawDeviceProperties — NVMe puts model string here
    // For NVMe (BusType=0x11=17), raw data contains NVMe Identify fields
    // For VMware NVMe, "VMWare NVME_0000" is likely in raw properties
    if (rawLen > 0 && rawLen < bufLen - 36) {
        PUCHAR rawPtr = descData + 36;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AceSpyDrv] RawDeviceProperties (len=%u): first 40 bytes: %.*s\n",
                 rawLen, rawLen < 40 ? rawLen : 40, rawPtr);

        // Search for "VMWare" or "NVME" in raw properties and replace
        // NVMe Identify Controller response: Serial at offset 4, Model at offset 24
        if (busType == 0x11 && rawLen >= 64) {  // BusTypeNvme = 17 = 0x11
            // NVMe Identify: Serial (offset 4, 20 bytes), Model (offset 24, 40 bytes), FW (offset 64, 8 bytes)
            PatchNvmeIdentify(rawPtr, rawLen);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AceSpyDrv] NVMe raw properties patched (Identify)\n");
        } else {
            // Generic: search for "VMWare" string and replace
            const char* targets[] = { "VMWare", "VMware", "NVME_0000", "NVMe" };
            const char* replacements[] = { "Seagat", "Seagat", "SSD_860QV", "SATA" };
            for (int t = 0; t < 4; t++) {
                size_t targetLen = strlen(targets[t]);
                if (targetLen >= rawLen) continue;
                for (ULONG i = 0; i + targetLen <= rawLen; i++) {
                    if (_strnicmp((const char*)(rawPtr + i), targets[t], targetLen) == 0) {
                        size_t replLen = strlen(replacements[t]);
                        if (replLen <= targetLen) {
                            RtlCopyMemory(rawPtr + i, replacements[t], replLen);
                            // Pad with spaces if replacement is shorter
                            for (size_t j = replLen; j < targetLen; j++)
                                rawPtr[i + j] = ' ';
                        } else {
                            RtlCopyMemory(rawPtr + i, replacements[t], targetLen);
                        }
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AceSpyDrv] Raw: replaced '%s' at offset %u\n", targets[t], i);
                    }
                }
            }
        }
    }
}

// ============================================================================
// STORAGE_PROTOCOL_DATA_DESCRIPTOR patch
// Response for IOCTL_STORAGE_QUERY_PROPERTY with PropertyId=25
// (StorageDeviceProtocolSpecificProperty) — contains NVMe Identify data
// ============================================================================
static void PatchStorageProtocolDataDescriptor(PUCHAR descData, ULONG bufLen) {
    if (!descData || bufLen < 48) return;

    // STORAGE_PROTOCOL_DATA_DESCRIPTOR:
    //   ULONG Version (offset 0)
    //   ULONG Size (offset 4)
    //   STORAGE_PROTOCOL_SPECIFIC_DATA ProtocolSpecificData (offset 8)
    //     ULONG ProtocolType (offset 8)  — 0x11 = NVMe
    //     ULONG DataType (offset 12)
    //     ULONG ProtocolDataRequestValue (offset 16)
    //     ULONG ProtocolDataRequestSubValue (offset 20)
    //     ULONG ProtocolDataOffset (offset 24)  — from start of ProtocolSpecificData
    //     ULONG ProtocolDataLength (offset 28)
    //     ...

    ULONG protocolType = *(ULONG*)(descData + 8);
    ULONG dataType = *(ULONG*)(descData + 12);
    ULONG dataOff = *(ULONG*)(descData + 24);   // ProtocolDataOffset
    ULONG dataLen = *(ULONG*)(descData + 28);   // ProtocolDataLength

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[AceSpyDrv] ProtocolDesc: type=%u dataType=%u dataOff=%u dataLen=%u\n",
               protocolType, dataType, dataOff, dataLen);

    // ProtocolType=0x11 (NVMe), DataType=1 (Identify)
    if (protocolType != 0x11) return;

    // NVMe Identify Controller data starts at: descData + 8 + dataOff
    // (8 = STORAGE_PROTOCOL_DATA_DESCRIPTOR header, dataOff = offset from ProtocolSpecificData)
    ULONG nvmeDataOff = 8 + dataOff;
    if (nvmeDataOff + 72 > bufLen || dataLen < 72) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[AceSpyDrv] ProtocolDesc: data too small (off=%u len=%u bufLen=%u)\n",
                   nvmeDataOff, dataLen, bufLen);
        return;
    }

    PUCHAR nvmeData = descData + nvmeDataOff;

    // Log original NVMe Identify fields
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[AceSpyDrv] NVMe Identify: serial=%.*s model=%.*s fw=%.*s\n",
               20, nvmeData + 4, 40, nvmeData + 24, 8, nvmeData + 64);

    // Patch using existing PatchNvmeIdentify
    PatchNvmeIdentify(nvmeData, dataLen);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[AceSpyDrv] ProtocolDesc NVMe Identify patched\n");
}

// ============================================================================
// NVMe STORAGE_PROTOCOL_COMMAND response patch
// WDK defines STORAGE_PROTOCOL_COMMAND with:
//   ProtocolType, DataFromDeviceTransferLength, DataFromDeviceBufferOffset, Command[]
// Handles both Identify (patch serial/model/fw) and Get Log Page (zero health/wear)
// ============================================================================
static void PatchNvmeProtocolCommand(PUCHAR systemBuffer, ULONG bufLen) {
    if (!systemBuffer || bufLen < sizeof(STORAGE_PROTOCOL_COMMAND)) return;
    PSTORAGE_PROTOCOL_COMMAND cmd = (PSTORAGE_PROTOCOL_COMMAND)systemBuffer;
    if (cmd->ProtocolType != ProtocolTypeNvme) return;
    if (cmd->DataFromDeviceTransferLength == 0 || cmd->DataFromDeviceBufferOffset == 0) return;
    if (cmd->DataFromDeviceBufferOffset + cmd->DataFromDeviceTransferLength > bufLen) return;

    PUCHAR protoData = systemBuffer + cmd->DataFromDeviceBufferOffset;
    ULONG protoLen = cmd->DataFromDeviceTransferLength;

    // Check CommandSpecific: 0x01 = NVMe Admin, 0x02 = NVMe NVM
    // NVMe Identify = opcode 0x06, Get Log Page = opcode 0x02
    // The Command[] field contains the NVMe command DWs
    // DW0 byte 0 = opcode
    if (cmd->CommandLength >= 1) {
        UCHAR opcode = cmd->Command[0];
        if (opcode == 0x06) {
            // Identify — patch serial/model/fw/EUI64
            PatchNvmeIdentify(protoData, protoLen);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[AceSpyDrv] NVMe protocol Identify patched\n");
        } else if (opcode == 0x02) {
            // Get Log Page — zero health/wear data to prevent fingerprinting
            // Log page 0x02 = SMART/Health: contains temperature, power-on hours,
            // power cycles, unsafe shutdowns, media wear, etc.
            // Log page 0x06 = Features: contains controller features
            // We zero the data portion (after the 8-byte log page header)
            if (protoLen > 8) {
                RtlZeroMemory(protoData + 8, protoLen - 8);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[AceSpyDrv] NVMe Get Log Page zeroed (%u bytes)\n", protoLen - 8);
            }
        }
    }
}

// ============================================================================
// IOCTL_SCSI_GET_INQUIRY_DATA response patch
// ============================================================================
static void PatchScsiInquiryData(PUCHAR systemBuffer, ULONG bufLen) {
    if (!systemBuffer || bufLen < 8) return;
    // IOCTL_SCSI_GET_INQUIRY_DATA returns SCSI_ADAPTER_BUS_INFO:
    //   UCHAR NumberOfBuses
    //   SCSI_BUS_DATA BusData[NumberOfBuses]
    // Each SCSI_BUS_DATA: UCHAR NumberOfLogicalUnits + UCHAR InitiatorBusId + ULONG InquiryDataOffset
    // = 8 bytes per bus entry (aligned)
    UCHAR numBuses = systemBuffer[0];
    for (UCHAR bus = 0; bus < numBuses; bus++) {
        ULONG busOff = 1 + bus * 8;  // each bus entry is 8 bytes
        if (busOff + 8 > bufLen) break;
        ULONG inqOff = *(ULONG*)(systemBuffer + busOff + 4);
        if (inqOff == 0 || inqOff >= bufLen) continue;

        // Walk inquiry data entries
        ULONG cur = inqOff;
        while (cur + 8 < bufLen) {
            UCHAR pathId = systemBuffer[cur];
            UCHAR targetId = systemBuffer[cur + 1];
            UCHAR lun = systemBuffer[cur + 2];
            UCHAR claimed = systemBuffer[cur + 3];
            ULONG inqLen = *(ULONG*)(systemBuffer + cur + 4);
            ULONG nextOff = *(ULONG*)(systemBuffer + cur + 8);

            if (inqLen < 36 || cur + 12 + 36 > bufLen) break;

            PUCHAR inqData = systemBuffer + cur + 12;
            if (MmIsAddressValid(inqData) && MmIsAddressValid(inqData + 35)) {
                PatchScsiInquiry(inqData, inqLen);
            }

            if (nextOff == 0 || nextOff >= bufLen) break;
            cur = nextOff;
        }
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[AceSpyDrv] SCSI_GET_INQUIRY_DATA patched\n");
}

// ============================================================================
// MBR disk signature + GPT DiskGUID / partition GUID spoofing
// Called from IRP_MJ_READ completion when reading raw disk sectors.
// We only patch sector 0 (MBR) and sector 1 (GPT header) + sector 2+ (GPT entries).
// ============================================================================
static KSPIN_LOCK g_guidLock = {};
static UCHAR g_spoofedDiskSig[4] = {};
static UCHAR g_spoofedDiskGuid[16] = {};
static BOOLEAN g_guidInitialized = FALSE;

static void InitSpoofedGuids() {
    if (g_guidInitialized) return;
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_guidLock, &oldIrql);
    if (!g_guidInitialized) {
        LARGE_INTEGER seed;
        KeQuerySystemTime(&seed);
        ULONG state = (ULONG)(seed.LowPart ^ 0xDEADBEEF);
        for (int i = 0; i < 4; i++)
            g_spoofedDiskSig[i] = (UCHAR)(LcgNext(state) & 0xFF);
        for (int i = 0; i < 16; i++)
            g_spoofedDiskGuid[i] = (UCHAR)(LcgNext(state) & 0xFF);
        g_guidInitialized = TRUE;
    }
    KeReleaseSpinLock(&g_guidLock, oldIrql);
}

// Patch MBR sector (sector 0): disk signature at offset 0x1B8
static void PatchMbrSector(PUCHAR data, ULONG len) {
    if (!data || len < MBR_DISK_SIGNATURE_OFFSET + MBR_DISK_SIGNATURE_LEN) return;
    if (!MmIsAddressValid(data + MBR_DISK_SIGNATURE_OFFSET)) return;
    InitSpoofedGuids();
    RtlCopyMemory(data + MBR_DISK_SIGNATURE_OFFSET, g_spoofedDiskSig, MBR_DISK_SIGNATURE_LEN);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[AceSpyDrv] MBR disk signature patched\n");
}

// Patch GPT header sector (sector 1): DiskGUID at offset 56
static void PatchGptHeaderSector(PUCHAR data, ULONG len) {
    if (!data || len < GPT_DISK_GUID_OFFSET + GPT_DISK_GUID_LEN) return;
    if (!MmIsAddressValid(data + GPT_DISK_GUID_OFFSET)) return;
    InitSpoofedGuids();
    RtlCopyMemory(data + GPT_DISK_GUID_OFFSET, g_spoofedDiskGuid, GPT_DISK_GUID_LEN);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[AceSpyDrv] GPT DiskGUID patched\n");
}

// Patch GPT partition entries (sector 2+): unique partition GUID at offset 16 of each 128-byte entry
static void PatchGptPartitionEntries(PUCHAR data, ULONG len) {
    if (!data || len < GPT_PART_ENTRY_SIZE) return;
    InitSpoofedGuids();
    ULONG entries = len / GPT_PART_ENTRY_SIZE;
    for (ULONG i = 0; i < entries && i < 128; i++) {
        PUCHAR entry = data + i * GPT_PART_ENTRY_SIZE;
        ULONG off = GPT_PART_UNIQUE_GUID_OFFSET;
        if (off + GPT_PART_UNIQUE_GUID_LEN > len) break;
        if (!MmIsAddressValid(entry + off)) break;
        // Only patch if the GUID is not all-zeros (valid partition entry)
        BOOLEAN hasData = FALSE;
        for (int j = 0; j < 16; j++) {
            if (entry[off + j] != 0) { hasData = TRUE; break; }
        }
        if (hasData) {
            // Use disk GUID as seed to generate stable per-partition GUID
            ULONG seed = HashBytes(entry + off, 16) ^ 0xCAFEBABE;
            for (int j = 0; j < 16; j++)
                entry[off + j] = (UCHAR)(LcgNext(seed) & 0xFF);
        }
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[AceSpyDrv] GPT partition GUIDs patched (%u entries)\n", entries);
}

// ============================================================================
// Read completion — patches MBR/GPT sectors based on starting byte offset
// ============================================================================
static NTSTATUS ReadCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context) {
    UNREFERENCED_PARAMETER(DeviceObject);
    ReadCtx* ctx = (ReadCtx*)Context;
    if (!ctx) {
        if (Irp->PendingReturned) IoMarkIrpPending(Irp);
        return STATUS_SUCCESS;
    }

    if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information > 0) {
        ULONG infoLen = (ULONG)Irp->IoStatus.Information;
        LARGE_INTEGER startOffset = ctx->startingOffset;
        ULONG readLen = ctx->readLength;

        // Get the data buffer
        PUCHAR dataBuf = nullptr;
        if (Irp->MdlAddress) {
            dataBuf = (PUCHAR)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
        } else if (Irp->AssociatedIrp.SystemBuffer) {
            dataBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
        } else if (Irp->UserBuffer) {
            dataBuf = (PUCHAR)Irp->UserBuffer;
        }

        if (dataBuf && MmIsAddressValid(dataBuf)) {
            // Determine which sector(s) are being read
            // startOffset is byte offset from beginning of disk
            ULONGLONG byteOffset = (ULONGLONG)startOffset.QuadPart;
            ULONG sectorSize = 512;  // assume 512-byte sectors (most common)

            // Sector 0 = MBR
            if (byteOffset == 0 && infoLen >= 512) {
                PatchMbrSector(dataBuf, infoLen);
            }
            // Sector 1 = GPT header
            else if (byteOffset == sectorSize && infoLen >= GPT_DISK_GUID_OFFSET + GPT_DISK_GUID_LEN) {
                // Verify this is actually GPT (signature "EFI PART" at offset 0)
                if (infoLen >= 8 && dataBuf[0] == 'E' && dataBuf[1] == 'F' &&
                    dataBuf[2] == 'I' && dataBuf[3] == ' ' &&
                    dataBuf[4] == 'P' && dataBuf[5] == 'A' &&
                    dataBuf[6] == 'R' && dataBuf[7] == 'T') {
                    PatchGptHeaderSector(dataBuf, infoLen);
                }
            }
            // Sector 2+ = GPT partition entries (typically sector 2-33)
            else if (byteOffset >= (ULONGLONG)sectorSize * 2 &&
                     byteOffset < (ULONGLONG)sectorSize * 34) {
                PatchGptPartitionEntries(dataBuf, infoLen);
            }
        }
    }

    ExFreePoolWithTag(ctx, 'rCAc');
    if (Irp->PendingReturned) IoMarkIrpPending(Irp);
    return STATUS_SUCCESS;
}

// ============================================================================
// Check if IOCTL is one we intercept
// ============================================================================
// Vendor-specific Samsung NVMe IOCTL (device type 0x4D, function 2)
#define IOCTL_SAMSUNG_NVME_4D0008  0x004D0008

static BOOLEAN IsTargetIoctl(ULONG code) {
    switch (code) {
    case SMART_RCV_DRIVE_DATA:
    case IOCTL_ATA_PASS_THROUGH:
    case IOCTL_ATA_PASS_THROUGH_DIRECT:
    case IOCTL_ATA_PASS_THROUGH_DIRECT_EX:
    case IOCTL_SCSI_PASS_THROUGH:
    case IOCTL_SCSI_PASS_THROUGH_EX:
    case IOCTL_SCSI_PASS_THROUGH_DIRECT:
    case IOCTL_SCSI_PASS_THROUGH_DIRECT_EX:
    case IOCTL_SCSI_GET_INQUIRY_DATA:
    case IOCTL_STORAGE_QUERY_PROPERTY:
    case IOCTL_STORAGE_PROTOCOL_COMMAND:
    case NVME_PASS_THROUGH_SRB_IO_CODE:
    case IOCTL_INTEL_NVME_PASS_THROUGH:
    case IOCTL_SCSI_MINIPORT:
    case IOCTL_SAMSUNG_NVME_4D0008:
        return TRUE;
    default:
        return FALSE;
    }
}

// Check if IOCTL is DIRECT (needs MDL mapping for user DataBuffer)
static BOOLEAN IsDirectIoctl(ULONG code) {
    switch (code) {
    case IOCTL_ATA_PASS_THROUGH_DIRECT:
    case IOCTL_ATA_PASS_THROUGH_DIRECT_EX:
    case IOCTL_SCSI_PASS_THROUGH_DIRECT:
    case IOCTL_SCSI_PASS_THROUGH_DIRECT_EX:
        return TRUE;
    default:
        return FALSE;
    }
}

// ============================================================================
// Patch METHOD_BUFFERED IOCTL response (system buffer, safe at any IRQL)
// ============================================================================
static void PatchBufferedIoctl(BufferedCtx* ctx, PIRP Irp) {
    if (!NT_SUCCESS(Irp->IoStatus.Status) || Irp->IoStatus.Information == 0) return;

    ULONG code = ctx->code;
    PVOID systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG infoLen = (ULONG)Irp->IoStatus.Information;
    if (!systemBuffer || !MmIsAddressValid(systemBuffer)) return;

    switch (code) {
    case SMART_RCV_DRIVE_DATA:
        if (infoLen >= (ULONG)(SENDCMDOUTPARAMS_BUFFER_OFFSET + 512)) {
            PUCHAR identifyData = (PUCHAR)systemBuffer + SENDCMDOUTPARAMS_BUFFER_OFFSET;
            if (MmIsAddressValid(identifyData) && MmIsAddressValid(identifyData + 511)) {
                PatchAtaIdentify(identifyData, 512);
                // Also zero SMART attributes if this is a SMART data read
                ZeroSmartAttributes(identifyData, infoLen - SENDCMDOUTPARAMS_BUFFER_OFFSET);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[AceSpyDrv] SMART_RCV_DRIVE_DATA patched\n");
            }
        }
        break;

    case IOCTL_ATA_PASS_THROUGH: {
        PATA_PASS_THROUGH_EX apte = (PATA_PASS_THROUGH_EX)systemBuffer;
        if (infoLen >= sizeof(ATA_PASS_THROUGH_EX) && apte->CurrentTaskFile[6] == 0xEC) {
            ULONG dataOffset = (ULONG)apte->DataBufferOffset;
            if (dataOffset >= sizeof(ATA_PASS_THROUGH_EX) && apte->DataTransferLength >= 512 &&
                dataOffset + 512 <= infoLen) {
                PUCHAR identifyData = (PUCHAR)systemBuffer + dataOffset;
                if (MmIsAddressValid(identifyData) && MmIsAddressValid(identifyData + 511)) {
                    PatchAtaIdentify(identifyData, 512);
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                               "[AceSpyDrv] ATA_PASS_THROUGH patched (IDENTIFY)\n");
                }
            }
        }
        break;
    }

    case IOCTL_SCSI_PASS_THROUGH:
    case IOCTL_SCSI_PASS_THROUGH_EX: {
        // Non-EX uses DataBufferOffset; EX uses DataInBufferOffset
        PSCSI_PASS_THROUGH spt = (PSCSI_PASS_THROUGH)systemBuffer;
        PSCSI_PASS_THROUGH_EX sptex = (PSCSI_PASS_THROUGH_EX)systemBuffer;
        ULONG dataOffset = 0;
        ULONG xferLen = 0;
        UCHAR cdb0 = 0;

        if (code == IOCTL_SCSI_PASS_THROUGH) {
            if (infoLen < sizeof(SCSI_PASS_THROUGH)) break;
            dataOffset = spt->DataBufferOffset;
            xferLen = spt->DataTransferLength;
            cdb0 = spt->Cdb[0];
        } else {
            if (infoLen < sizeof(SCSI_PASS_THROUGH_EX)) break;
            dataOffset = (ULONG)sptex->DataInBufferOffset;
            xferLen = sptex->DataInTransferLength;
            cdb0 = sptex->Cdb[0];
        }

        if (cdb0 == 0x12 && dataOffset > 0 && xferLen >= 36 && dataOffset + 36 <= infoLen) {
            PUCHAR inquiryData = (PUCHAR)systemBuffer + dataOffset;
            if (MmIsAddressValid(inquiryData) && MmIsAddressValid(inquiryData + 35)) {
                PatchScsiInquiry(inquiryData, xferLen);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[AceSpyDrv] SCSI_PASS_THROUGH%s patched (INQUIRY)\n",
                           code == IOCTL_SCSI_PASS_THROUGH_EX ? "_EX" : "");
            }
        }

        // Samsung NVMe: SECURITY PROTOCOL IN (Cdb[0]=0xA2, Cdb[1]=0xFE)
        // Response contains NVMe Identify Controller data (serial at offset 4, model at offset 24, fw at offset 64)
        if (cdb0 == 0xA2 && dataOffset > 0 && xferLen >= 72 && dataOffset + 72 <= infoLen) {
            PUCHAR nvmeData = (PUCHAR)systemBuffer + dataOffset;
            if (MmIsAddressValid(nvmeData) && MmIsAddressValid(nvmeData + 71)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[AceSpyDrv] SCSI_PASS_THROUGH SECURITY PROTOCOL IN: serial=%.*s model=%.*s fw=%.*s\n",
                           20, nvmeData + 4, 40, nvmeData + 24, 8, nvmeData + 64);
                PatchNvmeIdentify(nvmeData, xferLen);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[AceSpyDrv] SCSI_PASS_THROUGH patched (Samsung NVMe Identify)\n");
            }
        }
        break;
    }

    case IOCTL_SCSI_GET_INQUIRY_DATA:
        PatchScsiInquiryData((PUCHAR)systemBuffer, infoLen);
        break;

    case IOCTL_STORAGE_QUERY_PROPERTY: {
        // Response depends on PropertyId:
        //   PropertyId=0  (StorageDeviceProperty) -> STORAGE_DEVICE_DESCRIPTOR
        //   PropertyId=2  (StorageDeviceIdProperty) -> STORAGE_DEVICE_ID_DESCRIPTOR
        //   PropertyId=25 (StorageDeviceProtocolSpecificProperty) -> STORAGE_PROTOCOL_DATA_DESCRIPTOR (NVMe Identify)
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[AceSpyDrv] STORAGE_QUERY_PROPERTY PropertyId=%u\n", ctx->propertyId);

        if (ctx->propertyId == 0) {
            // StorageDeviceProperty -> STORAGE_DEVICE_DESCRIPTOR
            PatchStorageDeviceDescriptor((PUCHAR)systemBuffer, infoLen);
        } else if (ctx->propertyId == 25) {
            // StorageDeviceProtocolSpecificProperty -> NVMe Identify data
            PatchStorageProtocolDataDescriptor((PUCHAR)systemBuffer, infoLen);
        }

        // Generic: search entire buffer for "VMWare" / "NVME_0000" / "SAMSUNG" and replace
        {
            const char* targets[] = { "VMWare", "VMware", "NVME_0000", "NVME", "SAMSUNG", "MZVL" };
            const char* replacements[] = { "Seagat", "Seagat", "SSD_860QV", "SATA", "Seagate", "ST" };
            for (int t = 0; t < 6; t++) {
                size_t tLen = strlen(targets[t]);
                if (tLen >= infoLen) continue;
                for (ULONG i = 0; i + (ULONG)tLen <= infoLen; i++) {
                    if (_strnicmp((const char*)((PUCHAR)systemBuffer + i), targets[t], tLen) == 0) {
                        size_t rLen = strlen(replacements[t]);
                        ULONG copyLen = (ULONG)(rLen < tLen ? rLen : tLen);
                        RtlCopyMemory((PUCHAR)systemBuffer + i, replacements[t], copyLen);
                        // Pad with spaces if replacement shorter
                        for (ULONG j = copyLen; j < (ULONG)tLen; j++)
                            ((PUCHAR)systemBuffer)[i + j] = ' ';
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                                   "[AceSpyDrv] Generic: replaced '%s' at offset %u\n", targets[t], i);
                    }
                }
            }
        }
        break;
    }

    case IOCTL_STORAGE_PROTOCOL_COMMAND:
        PatchNvmeProtocolCommand((PUCHAR)systemBuffer, infoLen);
        break;

    case NVME_PASS_THROUGH_SRB_IO_CODE:
    case IOCTL_INTEL_NVME_PASS_THROUGH: {
        // NVMe pass-through: data buffer follows SRB_IO_CONTROL header
        // SRB_IO_CONTROL = 48 bytes header, then NVMe command + data
        // For Identify Controller (CNS=1), response has serial at offset 4
        if (infoLen >= 48 + 4096) {
            PUCHAR nvmeData = (PUCHAR)systemBuffer + 48;
            PatchNvmeIdentify(nvmeData, (ULONG)(infoLen - 48));
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[AceSpyDrv] NVMe pass-through patched\n");
        }
        break;
    }

    case IOCTL_SCSI_MINIPORT: {
        // SRB_IO_CONTROL header (28 bytes):
        //   ULONG HeaderLength (0)
        //   UCHAR Signature[8] (4)
        //   ULONG Timeout (12)
        //   ULONG ControlCode (16)
        //   ULONG ReturnCode (20)
        //   ULONG Length (24)
        // Data follows after HeaderLength bytes.
        if (infoLen < 28) break;

        PSRB_IO_CONTROL srb = (PSRB_IO_CONTROL)systemBuffer;
        ULONG hdrLen = srb->HeaderLength;
        ULONG srbLen = srb->Length;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[AceSpyDrv] SCSI_MINIPORT: hdrLen=%u sig='%.*s' controlCode=0x%X ret=%u len=%u\n",
                   hdrLen, 8, srb->Signature, srb->ControlCode, srb->ReturnCode, srbLen);

        // Data starts at hdrLen offset, length = srbLen (or infoLen - hdrLen)
        if (hdrLen < 28 || hdrLen >= infoLen) break;
        PUCHAR dataBuf = (PUCHAR)systemBuffer + hdrLen;
        ULONG dataLen = infoLen - hdrLen;
        if (srbLen > 0 && srbLen < dataLen) dataLen = srbLen;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[AceSpyDrv] SCSI_MINIPORT data: off=%u len=%u first 40 bytes: %.*s\n",
                   hdrLen, dataLen, dataLen < 40 ? dataLen : 40, dataBuf);

        // NVMe Identify Controller data: serial at offset 4 (20 bytes),
        // model at offset 24 (40 bytes), firmware at offset 64 (8 bytes)
        // Try patching if data looks like NVMe Identify (>= 72 bytes)
        if (dataLen >= 72) {
            // Check if this looks like NVMe Identify (serial/model/fw are printable ASCII)
            PUCHAR serialPtr = dataBuf + 4;
            PUCHAR modelPtr = dataBuf + 24;
            bool looksLikeNvme = true;
            for (int i = 0; i < 8 && looksLikeNvme; i++) {
                UCHAR c = serialPtr[i];
                if (c != 0 && c != ' ' && (c < 0x20 || c > 0x7E)) looksLikeNvme = false;
            }
            for (int i = 0; i < 8 && looksLikeNvme; i++) {
                UCHAR c = modelPtr[i];
                if (c != 0 && c != ' ' && (c < 0x20 || c > 0x7E)) looksLikeNvme = false;
            }

            if (looksLikeNvme) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[AceSpyDrv] SCSI_MINIPORT NVMe Identify detected: serial=%.*s model=%.*s fw=%.*s\n",
                           20, serialPtr, 40, modelPtr, 8, dataBuf + 64);
                PatchNvmeIdentify(dataBuf, dataLen);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[AceSpyDrv] SCSI_MINIPORT NVMe Identify patched\n");
            }
        }

        // Also do generic search-and-replace for known strings
        {
            const char* targets[] = { "SAMSUNG", "Samsung", "MZVL", "NVMe", "VMWare", "VMware" };
            const char* replacements[] = { "Seagate", "Seagate", "ST", "SATA", "Seagat", "Seagat" };
            for (int t = 0; t < 6; t++) {
                size_t tLen = strlen(targets[t]);
                if (tLen >= dataLen) continue;
                for (ULONG i = 0; i + (ULONG)tLen <= dataLen; i++) {
                    if (_strnicmp((const char*)(dataBuf + i), targets[t], tLen) == 0) {
                        size_t rLen = strlen(replacements[t]);
                        ULONG copyLen = (ULONG)(rLen < tLen ? rLen : tLen);
                        RtlCopyMemory(dataBuf + i, replacements[t], copyLen);
                        for (ULONG j = copyLen; j < (ULONG)tLen; j++)
                            dataBuf[i + j] = ' ';
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                                   "[AceSpyDrv] SCSI_MINIPORT generic: replaced '%s' at offset %u\n",
                                   targets[t], i);
                    }
                }
            }
        }
        break;
    }

    case IOCTL_SAMSUNG_NVME_4D0008: {
        // Vendor-specific Samsung NVMe IOCTL (device type 0x4D, function 2)
        // Unknown structure — dump first 128 bytes and do generic patch
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[AceSpyDrv] SAMSUNG_NVME_4D0008: infoLen=%u first 128 bytes:\n", infoLen);
        // Hex dump first 128 bytes
        PUCHAR buf = (PUCHAR)systemBuffer;
        for (ULONG i = 0; i < 128 && i < infoLen; i += 16) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[AceSpyDrv]   %03X: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X  %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n",
                       i,
                       buf[i], buf[i+1], buf[i+2], buf[i+3], buf[i+4], buf[i+5], buf[i+6], buf[i+7],
                       buf[i+8], buf[i+9], buf[i+10], buf[i+11], buf[i+12], buf[i+13], buf[i+14], buf[i+15],
                       (buf[i] >= 0x20 && buf[i] < 0x7F) ? buf[i] : '.',
                       (buf[i+1] >= 0x20 && buf[i+1] < 0x7F) ? buf[i+1] : '.',
                       (buf[i+2] >= 0x20 && buf[i+2] < 0x7F) ? buf[i+2] : '.',
                       (buf[i+3] >= 0x20 && buf[i+3] < 0x7F) ? buf[i+3] : '.',
                       (buf[i+4] >= 0x20 && buf[i+4] < 0x7F) ? buf[i+4] : '.',
                       (buf[i+5] >= 0x20 && buf[i+5] < 0x7F) ? buf[i+5] : '.',
                       (buf[i+6] >= 0x20 && buf[i+6] < 0x7F) ? buf[i+6] : '.',
                       (buf[i+7] >= 0x20 && buf[i+7] < 0x7F) ? buf[i+7] : '.',
                       (buf[i+8] >= 0x20 && buf[i+8] < 0x7F) ? buf[i+8] : '.',
                       (buf[i+9] >= 0x20 && buf[i+9] < 0x7F) ? buf[i+9] : '.',
                       (buf[i+10] >= 0x20 && buf[i+10] < 0x7F) ? buf[i+10] : '.',
                       (buf[i+11] >= 0x20 && buf[i+11] < 0x7F) ? buf[i+11] : '.',
                       (buf[i+12] >= 0x20 && buf[i+12] < 0x7F) ? buf[i+12] : '.',
                       (buf[i+13] >= 0x20 && buf[i+13] < 0x7F) ? buf[i+13] : '.',
                       (buf[i+14] >= 0x20 && buf[i+14] < 0x7F) ? buf[i+14] : '.',
                       (buf[i+15] >= 0x20 && buf[i+15] < 0x7F) ? buf[i+15] : '.');
        }

        // Try NVMe Identify layout: serial at offset 4, model at offset 24, fw at offset 64
        // But first check if there's an SRB_IO_CONTROL header (28 bytes)
        if (infoLen >= 28 + 72) {
            // Check if first 8 bytes look like a signature (printable ASCII)
            bool hasSrbHeader = true;
            for (int i = 0; i < 8; i++) {
                UCHAR c = buf[i];
                if (c != 0 && (c < 0x20 || c > 0x7E)) { hasSrbHeader = false; break; }
            }

            if (hasSrbHeader) {
                // SRB_IO_CONTROL header present, NVMe data starts at offset 28
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[AceSpyDrv] SAMSUNG_NVME: SRB header detected, NVMe data at offset 28\n");
                PUCHAR nvmeData = buf + 28;
                ULONG nvmeLen = infoLen - 28;
                if (nvmeLen >= 72) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                               "[AceSpyDrv] SAMSUNG_NVME: serial=%.*s model=%.*s fw=%.*s\n",
                               20, nvmeData + 4, 40, nvmeData + 24, 8, nvmeData + 64);
                    PatchNvmeIdentify(nvmeData, nvmeLen);
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                               "[AceSpyDrv] SAMSUNG_NVME: NVMe Identify patched (offset 28)\n");
                }
            } else if (infoLen >= 72) {
                // No SRB header — NVMe data starts at offset 0
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[AceSpyDrv] SAMSUNG_NVME: no SRB header, NVMe data at offset 0\n");
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[AceSpyDrv] SAMSUNG_NVME: serial=%.*s model=%.*s fw=%.*s\n",
                           20, buf + 4, 40, buf + 24, 8, buf + 64);
                PatchNvmeIdentify(buf, infoLen);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[AceSpyDrv] SAMSUNG_NVME: NVMe Identify patched (offset 0)\n");
            }
        }

        // Generic search-and-replace for known strings
        {
            const char* targets[] = { "SAMSUNG", "Samsung", "MZVL", "NVMe", "KXF71W1Q", "S7X8NF0Y533867" };
            const char* replacements[] = { "Seagate", "Seagate", "ST", "SATA", "ABC12345", "XXXXXXXXXXXXXXXX" };
            for (int t = 0; t < 6; t++) {
                size_t tLen = strlen(targets[t]);
                if (tLen >= infoLen) continue;
                for (ULONG i = 0; i + (ULONG)tLen <= infoLen; i++) {
                    if (_strnicmp((const char*)(buf + i), targets[t], tLen) == 0) {
                        size_t rLen = strlen(replacements[t]);
                        ULONG copyLen = (ULONG)(rLen < tLen ? rLen : tLen);
                        RtlCopyMemory(buf + i, replacements[t], copyLen);
                        for (ULONG j = copyLen; j < (ULONG)tLen; j++)
                            buf[i + j] = ' ';
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                                   "[AceSpyDrv] SAMSUNG_NVME generic: replaced '%s' at offset %u\n",
                                   targets[t], i);
                    }
                }
            }
        }
        break;
    }

    default:
        break;
    }
}

// ============================================================================
// Patch DIRECT IOCTL response (user DataBuffer mapped via MDL)
// ============================================================================
static void PatchDirectIoctl(DirectCtx* dctx, PIRP Irp) {
    if (!dctx || !dctx->mappedSystemVa) return;
    if (!NT_SUCCESS(Irp->IoStatus.Status)) return;

    PUCHAR dataBuf = (PUCHAR)dctx->mappedSystemVa;
    ULONG dataLen = dctx->dataLen;

    switch (dctx->ioctlCode) {
    case IOCTL_ATA_PASS_THROUGH_DIRECT:
    case IOCTL_ATA_PASS_THROUGH_DIRECT_EX:
        if (dctx->ataCommand == 0xEC && dataLen >= 512) {
            PatchAtaIdentify(dataBuf, 512);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[AceSpyDrv] ATA_PASS_THROUGH_DIRECT patched (IDENTIFY)\n");
        }
        break;

    case IOCTL_SCSI_PASS_THROUGH_DIRECT:
    case IOCTL_SCSI_PASS_THROUGH_DIRECT_EX:
        if (dctx->cdb0 == 0x12 && dataLen >= 36) {
            PatchScsiInquiry(dataBuf, dataLen);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[AceSpyDrv] SCSI_PASS_THROUGH_DIRECT patched (INQUIRY)\n");
        }
        // Samsung NVMe: SECURITY PROTOCOL IN (Cdb[0]=0xA2)
        if (dctx->cdb0 == 0xA2 && dataLen >= 72) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[AceSpyDrv] DIRECT SECURITY PROTOCOL IN: serial=%.*s model=%.*s fw=%.*s\n",
                       20, dataBuf + 4, 40, dataBuf + 24, 8, dataBuf + 64);
            PatchNvmeIdentify(dataBuf, dataLen);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[AceSpyDrv] SCSI_PASS_THROUGH_DIRECT patched (Samsung NVMe Identify)\n");
        }
        break;

    default:
        break;
    }
}

// ============================================================================
// SCSI INQUIRY response patch (for IRP_MJ_INTERNAL_DEVICE_CONTROL)
// ============================================================================
static void PatchInquiryResponse(PUCHAR data, ULONG dataLen) {
    if (!data || dataLen < 36) return;

    // SCSI INQUIRY response:
    //   offset 8:  Vendor Identification  (8 bytes)
    //   offset 16: Product Identification (16 bytes)
    //   offset 32: Product Revision Level (4 bytes)

    // Log original values
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[AceSpyDrv] INQUIRY before: vendor='%.*s' product='%.*s' rev='%.*s'\n",
               8, data + 8, 16, data + 16, 4, data + 32);

    // Patch vendor (8 bytes) — use first 8 chars of spoofed serial
    CHAR origVendor[9] = {};
    RtlCopyMemory(origVendor, data + 8, 8);
    int vLen = 8;
    while (vLen > 0 && (origVendor[vLen-1] == ' ' || origVendor[vLen-1] == '\0')) vLen--;
    if (vLen > 0) {
        CHAR spoofV[9] = {};
        if (GetSpoofSerial(origVendor, vLen, spoofV, 8)) {
            RtlCopyMemory(data + 8, spoofV, vLen);
            for (int i = vLen; i < 8; i++) data[8 + i] = ' ';
        }
    }

    // Patch product (16 bytes) — use a generic model name
    if (dataLen >= 32) {
        RtlCopyMemory(data + 16, "Samsung SSD 970 ", 16);
    }

    // Patch revision (4 bytes)
    if (dataLen >= 36) {
        RtlCopyMemory(data + 32, "2B2Q", 4);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[AceSpyDrv] INQUIRY after:  vendor='%.*s' product='%.*s' rev='%.*s'\n",
               8, data + 8, 16, data + 16, 4, data + 32);
}

// Try to patch data that looks like NVMe Identify Controller data
static void TryPatchNvmeIdentify(PUCHAR data, ULONG dataLen) {
    if (!data || dataLen < 72) return;

    // NVMe Identify Controller:
    //   offset 4:  Serial (20 bytes)
    //   offset 24: Model  (40 bytes)
    //   offset 64: FW     (8 bytes)

    // Check if offset 4 looks like a printable serial (NVMe identify check)
    bool looksLikeNvme = true;
    for (int i = 4; i < 24 && i < (int)dataLen; i++) {
        UCHAR c = data[i];
        if (c != 0 && c != ' ' && (c < 0x20 || c > 0x7E)) {
            looksLikeNvme = false;
            break;
        }
    }

    if (looksLikeNvme) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[AceSpyDrv] INTERNAL NVMe Identify: serial='%.*s' model='%.*s' fw='%.*s'\n",
                   20, data + 4, 40, data + 24, 8, data + 64);
        PatchNvmeIdentify(data, dataLen);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[AceSpyDrv] INTERNAL NVMe Identify patched\n");
    }
}

// ============================================================================
// Completion routines
// ============================================================================

// For IRP_MJ_INTERNAL_DEVICE_CONTROL — context is InternalCtx*
static NTSTATUS InternalCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context) {
    UNREFERENCED_PARAMETER(DeviceObject);
    InternalCtx* ctx = (InternalCtx*)Context;
    if (ctx) {
        if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information > 0) {
            // Get the data buffer from the SRB
            PUCHAR dataBuf = nullptr;
            ULONG dataLen = 0;

            // Try SRB DataBuffer first
            if (ctx->dataBuf && MmIsAddressValid(ctx->dataBuf)) {
                dataBuf = (PUCHAR)ctx->dataBuf;
                dataLen = ctx->dataLen;
            }

            // Also try IRP MdlAddress (SRB data might be MDL-mapped)
            if (!dataBuf && Irp->MdlAddress) {
                PVOID mapped = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
                if (mapped) {
                    dataBuf = (PUCHAR)mapped;
                    dataLen = (ULONG)Irp->IoStatus.Information;
                }
            }

            // Also try IRP AssociatedIrp.SystemBuffer
            if (!dataBuf && Irp->AssociatedIrp.SystemBuffer) {
                dataBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
                dataLen = (ULONG)Irp->IoStatus.Information;
            }

            if (dataBuf && dataLen > 0 && MmIsAddressValid(dataBuf)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[AceSpyDrv] INTERNAL_COMPLETION: cdb0=0x%X dataLen=%u first16=%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
                           ctx->cdb0, dataLen,
                           dataBuf[0], dataBuf[1], dataBuf[2], dataBuf[3],
                           dataBuf[4], dataBuf[5], dataBuf[6], dataBuf[7],
                           dataBuf[8], dataBuf[9], dataBuf[10], dataBuf[11],
                           dataBuf[12], dataBuf[13], dataBuf[14], dataBuf[15]);

                // Patch SCSI INQUIRY response
                if (ctx->cdb0 == 0x12 && dataLen >= 36) {
                    PatchInquiryResponse(dataBuf, dataLen);
                }

                // Try NVMe Identify patch (works for any data that looks like NVMe identify)
                TryPatchNvmeIdentify(dataBuf, dataLen);
            }
        }
        ExFreePoolWithTag(ctx, 'iCAc');
    }
    if (Irp->PendingReturned) IoMarkIrpPending(Irp);
    return STATUS_SUCCESS;
}

// For METHOD_BUFFERED IOCTLs — context is BufferedCtx*
static NTSTATUS BufferedCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context) {
    UNREFERENCED_PARAMETER(DeviceObject);
    BufferedCtx* ctx = (BufferedCtx*)Context;
    if (ctx) {
        PatchBufferedIoctl(ctx, Irp);
        ExFreePoolWithTag(ctx, 'cBAc');
    }
    if (Irp->PendingReturned) IoMarkIrpPending(Irp);
    return STATUS_SUCCESS;
}

// For DIRECT IOCTLs — context is DirectCtx* with MDL-mapped buffer
static NTSTATUS DirectCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context) {
    UNREFERENCED_PARAMETER(DeviceObject);
    DirectCtx* dctx = (DirectCtx*)Context;
    if (dctx) {
        PatchDirectIoctl(dctx, Irp);
        // Unmap and free MDL
        if (dctx->mdl) {
            if (dctx->mappedSystemVa)
                MmUnmapLockedPages(dctx->mappedSystemVa, dctx->mdl);
            IoFreeMdl(dctx->mdl);
        }
        ExFreePoolWithTag(dctx, 'dCAc');
    }
    if (Irp->PendingReturned) IoMarkIrpPending(Irp);
    return STATUS_SUCCESS;
}

// ============================================================================
// Filter dispatch
// ============================================================================
static FILTER_EXT* ExtOf(PDEVICE_OBJECT DeviceObject) {
    if (!DeviceObject || DeviceObject->DriverObject != g_driverObject) return nullptr;
    return (FILTER_EXT*)DeviceObject->DeviceExtension;
}

static NTSTATUS FilterPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    FILTER_EXT* ext = ExtOf(DeviceObject);
    if (!ext || !ext->lowerDevice) {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    // Log WMI IRPs (IRP_MJ_SYSTEM_CONTROL) — CrystalDiskInfo might use WMI
    PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(Irp);
    if (ioc->MajorFunction == IRP_MJ_SYSTEM_CONTROL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[AceSpyDrv] WMI IRP: minor=0x%X dev=%p\n",
                   ioc->MinorFunction, DeviceObject);
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->lowerDevice, Irp);
}

// ============================================================================
// FilterInternalDeviceControl — intercept IRP_MJ_INTERNAL_DEVICE_CONTROL
// This is how storage drivers send SCSI SRBs (including NVMe Identify) 
// between each other. The disk class driver converts user IOCTL_STORAGE_QUERY_PROPERTY
// to internal SRBs sent via IRP_MJ_INTERNAL_DEVICE_CONTROL to the port driver.
// ============================================================================
static NTSTATUS FilterInternalDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    FILTER_EXT* ext = ExtOf(DeviceObject);
    if (!ext || !ext->lowerDevice) {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(Irp);

    // For IRP_MJ_INTERNAL_DEVICE_CONTROL, the SRB is at Parameters.Scsi.Srb
    // which is at offset 0 of the Parameters union (same as Parameters.DeviceIoControl.Type3InputBuffer
    // on x86, but different on x64). We access it via raw pointer cast.
    PVOID srbPtr = *(PVOID*)&ioc->Parameters;

    if (srbPtr && MmIsAddressValid(srbPtr)) {
        PACESPY_SRB srb = (PACESPY_SRB)srbPtr;
        UCHAR srbFunc = srb->Function;
        UCHAR opcode = srb->OperationCode;
        USHORT dataLen = srb->DataTransferLength;
        PVOID dataBuf = srb->DataBuffer;

        // For legacy SRB_FUNCTION_EXECUTE_SCSI (0x00), Cdb is at offset 80
        UCHAR cdb0 = 0;
        if (srbFunc == ACESPY_SRB_FUNCTION_EXECUTE_SCSI) {
            cdb0 = srb->Cdb[0];
        } else if (srbFunc == ACESPY_SRB_FUNCTION_STORAGE_REQUEST_BLOCK) {
            // STORAGE_REQUEST_BLOCK — CDB is in extended data, log but don't parse for now
            cdb0 = 0xFF; // sentinel to indicate new format
        }

        // Log ALL internal SCSI IRPs to find the NVMe identify path
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[AceSpyDrv] INTERNAL_SCSI: dev=%p srb=%p func=0x%X op=0x%X cdb0=0x%X dataLen=%u dataBuf=%p\n",
                   DeviceObject, srbPtr, srbFunc, opcode, cdb0, dataLen, dataBuf);

        // Intercept SRBs that might carry identify data:
        // - SCSI INQUIRY (Cdb[0] = 0x12)
        // - SCSI SECURITY PROTOCOL IN (Cdb[0] = 0xA2) — Samsung NVMe uses this
        // - Any SRB with data buffer >= 72 bytes (might be NVMe Identify)
        BOOLEAN shouldIntercept = FALSE;
        if (srbFunc == ACESPY_SRB_FUNCTION_EXECUTE_SCSI) {
            if (cdb0 == 0x12 || cdb0 == 0xA2) {
                shouldIntercept = TRUE;
            }
            // Also intercept any SRB with large data buffer (might be NVMe identify)
            if (dataLen >= 72 && dataBuf) {
                shouldIntercept = TRUE;
            }
        } else if (srbFunc == ACESPY_SRB_FUNCTION_STORAGE_REQUEST_BLOCK) {
            // For new format, intercept if data buffer is large enough
            if (dataLen >= 72 && dataBuf) {
                shouldIntercept = TRUE;
            }
        }

        if (shouldIntercept) {
            InternalCtx* ctx = (InternalCtx*)ExAllocatePoolWithTag(
                NonPagedPool, sizeof(InternalCtx), 'iCAc');
            if (ctx) {
                RtlZeroMemory(ctx, sizeof(*ctx));
                ctx->srbPtr = srbPtr;
                ctx->srbFunction = srbFunc;
                ctx->cdb0 = cdb0;
                ctx->dataLen = dataLen;
                ctx->dataBuf = dataBuf;

                IoCopyCurrentIrpStackLocationToNext(Irp);
                IoSetCompletionRoutine(Irp, InternalCompletion, ctx, TRUE, TRUE, TRUE);
                return IoCallDriver(ext->lowerDevice, Irp);
            }
        }
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[AceSpyDrv] INTERNAL_SCSI: no SRB dev=%p ioc=%p\n",
                   DeviceObject, ioc);
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->lowerDevice, Irp);
}

static NTSTATUS FilterDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    FILTER_EXT* ext = ExtOf(DeviceObject);
    if (!ext || !ext->lowerDevice) {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = ioc->Parameters.DeviceIoControl.IoControlCode;

    // Log ALL IOCTLs to debug which ones CrystalDiskInfo uses
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AceSpyDrv] IOCTL 0x%08X dev=%p code=0x%X method=%d\n",
             code, DeviceObject, (code >> 2) & 0xFFF, code & 3);

    if (!IsTargetIoctl(code)) {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(ext->lowerDevice, Irp);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AceSpyDrv] TARGET IOCTL 0x%08X intercepted\n", code);

    // --- DIRECT IOCTLs: map user DataBuffer via MDL before sending down ---
    if (IsDirectIoctl(code)) {
        PVOID systemBuffer = Irp->AssociatedIrp.SystemBuffer;
        ULONG inputLen = ioc->Parameters.DeviceIoControl.InputBufferLength;

        // Extract DataBuffer pointer and length from struct
        PVOID userBuf = nullptr;
        ULONG dataLen = 0;
        UCHAR cdb0 = 0;
        UCHAR ataCmd = 0;

        if (systemBuffer && inputLen >= 40) {
            switch (code) {
            case IOCTL_ATA_PASS_THROUGH_DIRECT: {
                PATA_PASS_THROUGH_DIRECT aptd = (PATA_PASS_THROUGH_DIRECT)systemBuffer;
                userBuf = aptd->DataBuffer;
                dataLen = aptd->DataTransferLength;
                ataCmd = aptd->CurrentTaskFile[6];
                break;
            }
            case IOCTL_ATA_PASS_THROUGH_DIRECT_EX: {
                PATA_PASS_THROUGH_DIRECT_EX aptdex = (PATA_PASS_THROUGH_DIRECT_EX)systemBuffer;
                userBuf = aptdex->DataBuffer;
                dataLen = aptdex->DataTransferLength;
                ataCmd = aptdex->CurrentTaskFile[6];
                break;
            }
            case IOCTL_SCSI_PASS_THROUGH_DIRECT: {
                PSCSI_PASS_THROUGH_DIRECT sptd = (PSCSI_PASS_THROUGH_DIRECT)systemBuffer;
                userBuf = sptd->DataBuffer;
                dataLen = sptd->DataTransferLength;
                cdb0 = sptd->Cdb[0];
                break;
            }
            case IOCTL_SCSI_PASS_THROUGH_DIRECT_EX: {
                PSCSI_PASS_THROUGH_DIRECT_EX sptdex = (PSCSI_PASS_THROUGH_DIRECT_EX)systemBuffer;
                userBuf = sptdex->DataInBuffer;
                dataLen = sptdex->DataInTransferLength;
                cdb0 = sptdex->Cdb[0];
                break;
            }
            }
        }

        if (userBuf && dataLen > 0 && (ataCmd == 0xEC || cdb0 == 0x12 || cdb0 == 0xA2)) {
            // We're at PASSIVE_LEVEL in caller's context — safe to probe+lock
            DirectCtx* dctx = (DirectCtx*)ExAllocatePoolWithTag(
                NonPagedPool, sizeof(DirectCtx), 'dCAc');
            if (dctx) {
                RtlZeroMemory(dctx, sizeof(*dctx));
                dctx->ioctlCode = code;
                dctx->dataLen = dataLen;
                dctx->cdb0 = cdb0;
                dctx->ataCommand = ataCmd;

                // Create MDL for user buffer and lock it
                dctx->mdl = IoAllocateMdl(userBuf, dataLen, FALSE, FALSE, nullptr);
                if (dctx->mdl) {
                    __try {
                        MmProbeAndLockPages(dctx->mdl, UserMode, IoModifyAccess);
                        dctx->mappedSystemVa = MmGetSystemAddressForMdlSafe(
                            dctx->mdl, NormalPagePriority);
                        if (dctx->mappedSystemVa) {
                            IoCopyCurrentIrpStackLocationToNext(Irp);
                            IoSetCompletionRoutine(Irp, DirectCompletion, dctx, TRUE, TRUE, TRUE);
                            return IoCallDriver(ext->lowerDevice, Irp);
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        // Probe failed — user buffer invalid, skip patching
                    }
                    if (dctx->mdl) {
                        IoFreeMdl(dctx->mdl);
                        dctx->mdl = nullptr;
                    }
                }
                ExFreePoolWithTag(dctx, 'dCAc');
            }
        }

        // Fallback: pass through without patching
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(ext->lowerDevice, Irp);
    }

    // --- METHOD_BUFFERED IOCTLs ---
    // Alloc BufferedCtx to store IOCTL code + PropertyId
    BufferedCtx* bctx = (BufferedCtx*)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(BufferedCtx), 'cBAc');
    if (!bctx) {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(ext->lowerDevice, Irp);
    }
    bctx->code = code;
    bctx->propertyId = 0;

    // For IOCTL_STORAGE_QUERY_PROPERTY, read PropertyId from input buffer
    // Input buffer is STORAGE_PROPERTY_QUERY: ULONG PropertyId at offset 0
    if (code == IOCTL_STORAGE_QUERY_PROPERTY) {
        PVOID inBuf = Irp->AssociatedIrp.SystemBuffer;
        ULONG inLen = ioc->Parameters.DeviceIoControl.InputBufferLength;
        if (inBuf && inLen >= 4 && MmIsAddressValid(inBuf)) {
            bctx->propertyId = *(ULONG*)inBuf;
        }
    }

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, BufferedCompletion, bctx, TRUE, TRUE, TRUE);
    return IoCallDriver(ext->lowerDevice, Irp);
}

// ============================================================================
// FilterRead — intercept IRP_MJ_READ on PhysicalDrive to patch MBR/GPT
// ============================================================================
static NTSTATUS FilterRead(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    FILTER_EXT* ext = ExtOf(DeviceObject);
    if (!ext || !ext->lowerDevice) {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(Irp);

    // Only intercept reads of raw disk sectors (sector 0-33)
    // Reading byte offset 0 to ~17KB covers MBR + GPT header + partition entries
    ULONGLONG byteOffset = (ULONGLONG)ioc->Parameters.Read.ByteOffset.QuadPart;
    ULONG readLen = ioc->Parameters.Read.Length;

    // Only intercept if reading near the start of the disk (sectors 0-33 = 0-17KB)
    if (byteOffset >= 34 * 512 || readLen < 512) {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(ext->lowerDevice, Irp);
    }

    // Allocate read context
    ReadCtx* ctx = (ReadCtx*)ExAllocatePoolWithTag(NonPagedPool, sizeof(ReadCtx), 'rCAc');
    if (!ctx) {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(ext->lowerDevice, Irp);
    }

    ctx->startingOffset = ioc->Parameters.Read.ByteOffset;
    ctx->readLength = readLen;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, ReadCompletion, ctx, TRUE, TRUE, TRUE);
    return IoCallDriver(ext->lowerDevice, Irp);
}

// ============================================================================
// Attach to disk devices
// ============================================================================
static BOOLEAN AlreadyFiltered(PDEVICE_OBJECT target) {
    for (PDEVICE_OBJECT cur = target; cur; cur = cur->AttachedDevice) {
        if (cur->DriverObject == g_driverObject) return TRUE;
    }
    return FALSE;
}

static NTSTATUS AttachToDiskDevice(PDEVICE_OBJECT target) {
    if (!g_driverObject || !target || g_unloading) return STATUS_UNSUCCESSFUL;
    if (AlreadyFiltered(target)) return STATUS_SUCCESS;
    if (g_filterCount >= MAX_FILTERS) return STATUS_INSUFFICIENT_RESOURCES;

    PDEVICE_OBJECT filter = nullptr;
    NTSTATUS status = IoCreateDevice(
        g_driverObject, sizeof(FILTER_EXT), nullptr,
        target->DeviceType, target->Characteristics, FALSE, &filter);
    if (!NT_SUCCESS(status) || !filter) return status;

    FILTER_EXT* ext = (FILTER_EXT*)filter->DeviceExtension;
    RtlZeroMemory(ext, sizeof(*ext));
    ext->targetDevice = target;
    filter->Flags |= (target->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE));

    PDEVICE_OBJECT lower = IoAttachDeviceToDeviceStack(filter, target);
    if (!lower) { IoDeleteDevice(filter); return STATUS_NO_SUCH_DEVICE; }

    ext->lowerDevice = lower;
    filter->Flags &= ~DO_DEVICE_INITIALIZING;

    LONG idx = InterlockedIncrement(&g_filterCount) - 1;
    if (idx < MAX_FILTERS) g_filters[idx] = filter;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[AceSpyDrv] Attached filter %p -> %p\n", filter, target);
    return STATUS_SUCCESS;
}

static NTSTATUS AttachAllDiskDevices() {
    // Strategy: enumerate ALL drivers in \Driver directory and attach to any
    // that have device objects with type FILE_DEVICE_DISK (7) or 
    // FILE_DEVICE_CONTROLLER (4). This catches vendor-specific NVMe drivers
    // like Samsung NVMe, Intel NVMe, etc.
    
    UNICODE_STRING dirName = RTL_CONSTANT_STRING(L"\\Driver");
    HANDLE dirHandle = nullptr;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &dirName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    
    NTSTATUS status = ZwOpenDirectoryObject(&dirHandle, DIRECTORY_QUERY, &oa);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[AceSpyDrv] Cannot open \\Driver directory (0x%08X)\n", status);
        // Fallback: try known driver names
        const wchar_t* fallbackDrivers[] = {
            L"\\Driver\\Disk", L"\\Driver\\partmgr", L"\\Driver\\storahci",
            L"\\Driver\\stornvme", L"\\Driver\\disk"
        };
        for (int d = 0; d < 5; d++) {
            UNICODE_STRING drvName;
            RtlInitUnicodeString(&drvName, fallbackDrivers[d]);
            PDRIVER_OBJECT drvObj = nullptr;
            NTSTATUS s = ObReferenceObjectByName(&drvName, OBJ_CASE_INSENSITIVE, nullptr, 0,
                *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&drvObj);
            if (NT_SUCCESS(s) && drvObj) {
                ULONG needed = 0;
                IoEnumerateDeviceObjectList(drvObj, nullptr, 0, &needed);
                if (needed > 0) {
                    ULONG bytes = needed * sizeof(PDEVICE_OBJECT);
                    PDEVICE_OBJECT* list = (PDEVICE_OBJECT*)ExAllocatePoolWithTag(NonPagedPool, bytes, 'tAAc');
                    if (list) {
                        ULONG actual = 0;
                        IoEnumerateDeviceObjectList(drvObj, list, bytes, &actual);
                        for (ULONG i = 0; i < actual && i < needed; i++) {
                            if (list[i]) { AttachToDiskDevice(list[i]); ObDereferenceObject(list[i]); }
                        }
                        ExFreePoolWithTag(list, 'tAAc');
                    }
                }
                ObDereferenceObject(drvObj);
            }
        }
        return STATUS_SUCCESS;
    }

    // Enumerate directory entries
    ULONG context = 0;
    ULONG returned = 0;
    ULONG bufSize = 16384;
    PVOID dirBuf = ExAllocatePoolWithTag(NonPagedPool, bufSize, 'dBAc');
    if (!dirBuf) { ZwClose(dirHandle); return STATUS_INSUFFICIENT_RESOURCES; }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[AceSpyDrv] Enumerating \\Driver, sizeof(OBJECT_DIRECTORY_INFORMATION)=%u\n",
               (ULONG)sizeof(OBJECT_DIRECTORY_INFORMATION));

    BOOLEAN restart = TRUE;
    ULONG totalDrivers = 0;
    ULONG totalAttached = 0;
    while (TRUE) {
        status = ZwQueryDirectoryObject(dirHandle, dirBuf, bufSize, FALSE, restart, &context, &returned);
        restart = FALSE;
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[AceSpyDrv] ZwQueryDirectoryObject returned 0x%08X, returned=%u\n", status, returned);
            break;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[AceSpyDrv] ZwQueryDirectoryObject OK, returned=%u bytes\n", returned);

        // OBJECT_DIRECTORY_INFORMATION entries — array, no NextEntryOffset
        // sizeof(UNICODE_STRING) = 16 on x64 (USHORT Length + USHORT MaxLength + 4 pad + PTR Buffer)
        // sizeof(OBJECT_DIRECTORY_INFORMATION) = 32 (2x UNICODE_STRING)
        ULONG entrySize = sizeof(OBJECT_DIRECTORY_INFORMATION);
        ULONG numEntries = returned / entrySize;
        if (numEntries == 0) {
            // Maybe returned is count, not bytes
            numEntries = returned;
        }
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[AceSpyDrv] numEntries=%u (entrySize=%u)\n", numEntries, entrySize);

        POBJECT_DIRECTORY_INFORMATION entries = (POBJECT_DIRECTORY_INFORMATION)dirBuf;

        for (ULONG idx = 0; idx < numEntries && idx < 512; idx++) {
            POBJECT_DIRECTORY_INFORMATION entry = &entries[idx];

            // Validate pointers with __try/__except
            bool isDriver = false;
            WCHAR entryName[256] = {0};

            __try {
                // Check TypeName is "Driver"
                if (entry->TypeName.Length > 0 && entry->TypeName.Length <= 256 &&
                    entry->TypeName.Buffer &&
                    MmIsAddressValid(entry->TypeName.Buffer)) {

                    ULONG typeLen = entry->TypeName.Length / sizeof(WCHAR);
                    if (typeLen >= 6) {
                        if (_wcsnicmp(entry->TypeName.Buffer, L"Driver", 6) == 0) {
                            isDriver = true;
                            totalDrivers++;
                        }
                    }
                }

                // Copy Name if valid
                if (isDriver && entry->Name.Length > 0 && entry->Name.Length <= 500 &&
                    entry->Name.Buffer && MmIsAddressValid(entry->Name.Buffer)) {

                    ULONG nameLen = entry->Name.Length / sizeof(WCHAR);
                    if (nameLen > 248) nameLen = 248;
                    RtlCopyMemory(entryName, entry->Name.Buffer, nameLen * sizeof(WCHAR));
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                isDriver = false;
            }

            if (!isDriver || entryName[0] == 0) continue;

            // Build full path: \Driver\<name>
            WCHAR fullPath[256] = {0};
            // "\\Driver\\" is 8 chars including trailing backslash, but we need 7 chars + null
            // Actually L"\\Driver\\" = {'\\','D','r','i','v','e','r','\\',0} = 9 wchars with null
            // Copy 8 chars (including trailing backslash), then append name at offset 8
            RtlCopyMemory(fullPath, L"\\Driver\\", 8 * sizeof(WCHAR));
            ULONG nameLen = 0;
            while (entryName[nameLen] && nameLen < 247) nameLen++;
            RtlCopyMemory(fullPath + 8, entryName, nameLen * sizeof(WCHAR));

            UNICODE_STRING fullDrvName;
            RtlInitUnicodeString(&fullDrvName, fullPath);

            PDRIVER_OBJECT drvObj = nullptr;
            NTSTATUS refStatus = ObReferenceObjectByName(
                &fullDrvName, OBJ_CASE_INSENSITIVE, nullptr, 0,
                *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&drvObj);

            if (!NT_SUCCESS(refStatus) || !drvObj) {
                // Only log failures for known storage drivers to reduce noise
                if (_wcsnicmp(entryName, L"Disk", 4) == 0 ||
                    _wcsnicmp(entryName, L"stor", 4) == 0 ||
                    _wcsnicmp(entryName, L"partmgr", 7) == 0 ||
                    _wcsnicmp(entryName, L"disk", 4) == 0) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                               "[AceSpyDrv] Failed to reference %ws (0x%08X)\n", fullPath, refStatus);
                }
                continue;
            }

            ULONG needed = 0;
            IoEnumerateDeviceObjectList(drvObj, nullptr, 0, &needed);
            if (needed == 0) {
                ObDereferenceObject(drvObj);
                continue;
            }

            // Log ALL drivers that have device objects
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[AceSpyDrv] Driver %ws has %u device objects\n", fullPath, needed);

            ULONG bytes = needed * sizeof(PDEVICE_OBJECT);
            PDEVICE_OBJECT* list = (PDEVICE_OBJECT*)ExAllocatePoolWithTag(NonPagedPool, bytes, 'tAAc');
            if (!list) {
                ObDereferenceObject(drvObj);
                continue;
            }

            ULONG actual = 0;
            NTSTATUS enumStatus = IoEnumerateDeviceObjectList(drvObj, list, bytes, &actual);
            if (!NT_SUCCESS(enumStatus) && enumStatus != STATUS_BUFFER_TOO_SMALL) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[AceSpyDrv] IoEnumerateDeviceObjectList failed for %ws (0x%08X)\n",
                           fullPath, enumStatus);
                ExFreePoolWithTag(list, 'tAAc');
                ObDereferenceObject(drvObj);
                continue;
            }

            ULONG count = actual < needed ? actual : needed;
            bool hasDiskDevice = false;
            bool hasControllerDevice = false;

            for (ULONG i = 0; i < count; i++) {
                if (list[i]) {
                    // Log device type for ALL devices
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                               "[AceSpyDrv]   %ws dev[%u] type=0x%X flags=0x%X\n",
                               fullPath, i, list[i]->DeviceType, list[i]->Flags);
                    if (list[i]->DeviceType == FILE_DEVICE_DISK) hasDiskDevice = true;
                    if (list[i]->DeviceType == FILE_DEVICE_CONTROLLER) hasControllerDevice = true;
                }
            }

            if (hasDiskDevice || hasControllerDevice) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[AceSpyDrv] Driver %ws ATTACHING (disk=%d ctrl=%d)\n",
                           fullPath, hasDiskDevice, hasControllerDevice);

                for (ULONG i = 0; i < count; i++) {
                    if (list[i]) {
                        AttachToDiskDevice(list[i]);
                        ObDereferenceObject(list[i]);
                    }
                }
            }

            ExFreePoolWithTag(list, 'tAAc');
            ObDereferenceObject(drvObj);
        }

        if (status == STATUS_NO_MORE_ENTRIES) break;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[AceSpyDrv] Enum done: totalDrivers=%u, totalAttached=%d\n",
               totalDrivers, (int)g_filterCount);

    ExFreePoolWithTag(dirBuf, 'dBAc');
    ZwClose(dirHandle);
    return STATUS_SUCCESS;
}

static VOID AttachWorker(PVOID StartContext) {
    UNREFERENCED_PARAMETER(StartContext);
    LARGE_INTEGER delay;
    delay.QuadPart = ATTACH_DELAY_100NS;
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    if (!g_unloading && g_driverObject) {
        NTSTATUS status = AttachAllDiskDevices();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[AceSpyDrv] Attach finished: 0x%08X filters=%d\n",
                   status, (int)g_filterCount);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ============================================================================
// Unload
// ============================================================================
static VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    InterlockedExchange(&g_unloading, 1);

    LARGE_INTEGER delay;
    delay.QuadPart = -2LL * 1000 * 1000 * 10;
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    LONG count = g_filterCount;
    for (LONG i = 0; i < count && i < MAX_FILTERS; i++) {
        PDEVICE_OBJECT filter = g_filters[i];
        if (!filter) continue;
        FILTER_EXT* ext = (FILTER_EXT*)filter->DeviceExtension;
        if (ext && ext->lowerDevice) IoDetachDevice(ext->lowerDevice);
        IoDeleteDevice(filter);
        g_filters[i] = nullptr;
    }
    g_filterCount = 0;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AceSpyDrv] Unloaded\n");
}

// ============================================================================
// Entry
// ============================================================================
static NTSTATUS RealDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AceSpyDrv] RealDriverEntry drv=%p\n", DriverObject);
    g_driverObject = DriverObject;
    KeInitializeSpinLock(&g_cacheLock);

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = FilterPassThrough;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FilterDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_READ] = FilterRead;
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = FilterInternalDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    HANDLE thread = nullptr;
    NTSTATUS status = PsCreateSystemThread(
        &thread, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr, AttachWorker, nullptr);
    if (NT_SUCCESS(status) && thread) ZwClose(thread);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[AceSpyDrv] Filter ready, attach in 10s. Coverage: 14 IOCTLs\n");
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    // Use raw DbgPrint (not Ex) for entry — always shows in WinDbg, no filter
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AceSpyDrv] DriverEntry drv=%p reg=%p\n", DriverObject, RegistryPath);
    if (!DriverObject) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AceSpyDrv] DriverObject=NULL, calling IoCreateDriver\n");
        UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Driver\\AceSpyFlt");
        NTSTATUS s = IoCreateDriver(&name, RealDriverEntry);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AceSpyDrv] IoCreateDriver returned 0x%08X\n", s);
        return s;
    }
    return RealDriverEntry(DriverObject, RegistryPath);
}
