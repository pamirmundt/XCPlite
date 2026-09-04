// daq_config_test
// Tests dynamic DAQ configuration bounds and event-list linking through the XCP command processor.
// No network server or XCP client is required.
//
// Build:
//   cmake -B build -S . -DXCPLITE_BUILD_TESTS=ON
//   cmake --build build --target daq_config_test
// Run:
//   ./build/daq_config_test

#include <assert.h> // for assert
#include <stdint.h> // for uintxx_t
#include <stdio.h>  // for printf
#include <string.h> // for memcpy

// Public XCPlite API
#include "xcplib.h" // for XcpEventExt, XcpSetLogLevel

// Internal interfaces used to exercise the protocol command path without a network server.
#include "queue.h"    // for the transmit queue
#include "xcp.h"      // for XCP commands and error codes
#include "xcp_cfg.h"  // for dynamic address encoding
#include "xcplite.h"  // for the protocol-layer interface

//-----------------------------------------------------------------------------------------------------
// Test configuration

#define TEST_QUEUE_SIZE ((size_t)16 * 1024)

typedef union {
    uint32_t words[XCPTL_MAX_CTO_SIZE / sizeof(uint32_t)];
    uint8_t bytes[XCPTL_MAX_CTO_SIZE];
} tTestCommand;

static tQueueHandle test_queue;

//-----------------------------------------------------------------------------------------------------
// XCP command helpers

// Encode integers in the little-endian byte order required by XCP.
static void set_u16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void set_u32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static uint8_t run_command(const uint8_t *data, uint8_t size) {
    tTestCommand command = {0};
    memcpy(command.bytes, data, size);
    return XcpCommand(command.words, size);
}

// The following helpers construct complete XCP commands and execute them through XcpCommand().
static uint8_t free_daq(void) {
    const uint8_t command[] = {CC_FREE_DAQ};
    return run_command(command, sizeof(command));
}

static uint8_t alloc_daq(uint16_t count) {
    uint8_t command[CRO_ALLOC_DAQ_LEN] = {CC_ALLOC_DAQ};
    set_u16(&command[2], count);
    return run_command(command, sizeof(command));
}

static uint8_t alloc_odt(uint16_t daq, uint8_t count) {
    uint8_t command[CRO_ALLOC_ODT_LEN] = {CC_ALLOC_ODT};
    set_u16(&command[2], daq);
    command[4] = count;
    return run_command(command, sizeof(command));
}

static uint8_t alloc_odt_entry(uint16_t daq, uint8_t odt, uint8_t count) {
    uint8_t command[CRO_ALLOC_ODT_ENTRY_LEN] = {CC_ALLOC_ODT_ENTRY};
    set_u16(&command[2], daq);
    command[4] = odt;
    command[5] = count;
    return run_command(command, sizeof(command));
}

static uint8_t set_daq_ptr(uint16_t daq, uint8_t odt, uint8_t entry) {
    uint8_t command[CRO_SET_DAQ_PTR_LEN] = {CC_SET_DAQ_PTR};
    set_u16(&command[2], daq);
    command[4] = odt;
    command[5] = entry;
    return run_command(command, sizeof(command));
}

static uint8_t write_daq(uint8_t size, uint8_t ext, uint32_t addr) {
    uint8_t command[CRO_WRITE_DAQ_LEN] = {CC_WRITE_DAQ};
    command[2] = size;
    command[3] = ext;
    set_u32(&command[4], addr);
    return run_command(command, sizeof(command));
}

static uint8_t set_daq_list_mode(uint16_t daq, uint16_t event) {
    uint8_t command[CRO_SET_DAQ_LIST_MODE_LEN] = {CC_SET_DAQ_LIST_MODE};
    command[1] = DAQ_MODE_TIMESTAMP;
    set_u16(&command[2], daq);
    set_u16(&command[4], event);
    command[6] = 1;
    return run_command(command, sizeof(command));
}

static uint8_t start_stop_daq_list(uint16_t daq, uint8_t mode) {
    uint8_t command[CRO_START_STOP_DAQ_LIST_LEN] = {CC_START_STOP_DAQ_LIST};
    command[1] = mode;
    set_u16(&command[2], daq);
    return run_command(command, sizeof(command));
}

static uint8_t start_stop_synch(uint8_t mode) {
    const uint8_t command[CRO_START_STOP_SYNCH_LEN] = {CC_START_STOP_SYNCH, mode};
    return run_command(command, sizeof(command));
}

//-----------------------------------------------------------------------------------------------------
// Regression tests

// An oversized ALLOC_DAQ must be rejected before writing the DAQ table.
// A valid allocation immediately afterwards verifies that the rejected command did not alter the state.
static void test_daq_allocation_rollback(void) {
    assert(alloc_daq(UINT16_MAX) == CRC_MEMORY_OVERFLOW);
    assert(alloc_daq(1) == CRC_CMD_OK);
    assert(free_daq() == CRC_CMD_OK);
}

// The first ODT allocation fits in the configured DAQ memory; the second does not.
// Retrying with a smaller count verifies that the rejected allocation did not change the total ODT count.
static void test_odt_allocation_rollback(void) {
    assert(alloc_daq(2) == CRC_CMD_OK);
    assert(alloc_odt(0, 200) == CRC_CMD_OK);
    assert(alloc_odt(1, 200) == CRC_MEMORY_OVERFLOW);
    assert(alloc_odt(1, 1) == CRC_CMD_OK);
    assert(free_daq() == CRC_CMD_OK);
}

// Fill most of the DAQ memory with ODT entries, provoke an overflow, then retry with one entry.
// The retry succeeds only if the rejected allocation preserved the previous ODT entry count.
static void test_odt_entry_allocation_rollback(void) {
    assert(alloc_daq(1) == CRC_CMD_OK);
    assert(alloc_odt(0, 3) == CRC_CMD_OK);
    assert(alloc_odt_entry(0, 0, 200) == CRC_CMD_OK);
    assert(alloc_odt_entry(0, 1, 200) == CRC_CMD_OK);
    assert(alloc_odt_entry(0, 2, 200) == CRC_MEMORY_OVERFLOW);
    assert(alloc_odt_entry(0, 2, 1) == CRC_CMD_OK);
    assert(free_daq() == CRC_CMD_OK);
}

// Four maximum-size entries fit into the first ODT. The fifth exceeds the DTO limit.
// A smaller entry must still fit afterwards, proving that the failed write did not increase the ODT size.
static void test_odt_size_rollback(tXcpEventId event) {
    assert(alloc_daq(1) == CRC_CMD_OK);
    assert(alloc_odt(0, 1) == CRC_CMD_OK);
    assert(alloc_odt_entry(0, 0, 5) == CRC_CMD_OK);
    assert(set_daq_ptr(0, 0, 0) == CRC_CMD_OK);

    uint32_t addr = XcpAddrEncodeDyn(0, event);
    for (uint8_t i = 0; i < 4; i++) {
        assert(write_daq(XCPTL_MAX_CTO_SIZE, XCP_ADDR_EXT_DYN, addr) == CRC_CMD_OK);
    }
    assert(write_daq(XCPTL_MAX_CTO_SIZE, XCP_ADDR_EXT_DYN, addr) == CRC_DAQ_CONFIG);
    assert(write_daq(24, XCP_ADDR_EXT_DYN, addr) == CRC_CMD_OK);
    assert(free_daq() == CRC_CMD_OK);
}

static void configure_single_entry_daq(uint16_t daq, tXcpEventId event) {
    assert(set_daq_ptr(daq, 0, 0) == CRC_CMD_OK);
    assert(write_daq(sizeof(uint32_t), XCP_ADDR_EXT_DYN, XcpAddrEncodeDyn(0, event)) == CRC_CMD_OK);
    assert(set_daq_list_mode(daq, event) == CRC_CMD_OK);
}

// Associate two DAQ lists with one event and repeat one association.
// Triggering the event must produce one DTO per DAQ list without an out-of-bounds link or cycle.
static void test_shared_event_daq_list(tXcpEventId event) {
    assert(alloc_daq(2) == CRC_CMD_OK);
    assert(alloc_odt(0, 1) == CRC_CMD_OK);
    assert(alloc_odt(1, 1) == CRC_CMD_OK);
    assert(alloc_odt_entry(0, 0, 1) == CRC_CMD_OK);
    assert(alloc_odt_entry(1, 0, 1) == CRC_CMD_OK);
    configure_single_entry_daq(0, event);
    configure_single_entry_daq(1, event);

    // Repeating the association must not append the same DAQ list again or form a cycle.
    assert(set_daq_list_mode(0, event) == CRC_CMD_OK);

    assert(start_stop_daq_list(0, 2) == CRC_CMD_OK);
    assert(start_stop_daq_list(1, 2) == CRC_CMD_OK);
    assert(start_stop_synch(1) == CRC_CMD_OK);

    uint32_t measurement = 0x12345678;
    XcpEventExt(event, (const uint8_t *)&measurement);

    // Both DAQ lists must be reached exactly once through the event's linked list.
    uint8_t dto_count = 0;
    for (;;) {
        tQueueBuffer dto = queuePeek(test_queue, 0, NULL, NULL);
        if (dto.buffer == NULL)
            break;
        dto_count++;
        queueRelease(test_queue, &dto);
    }
    assert(dto_count == 2);
}

//-----------------------------------------------------------------------------------------------------
// Main

int main(void) {
    XcpSetLogLevel(0);
    assert(XcpInit("daq_config_test", "1.0", XCP_MODE_LOCAL));

    tXcpEventId event = XcpCreateEvent("test_event", 1000000, 0);
    assert(event != XCP_UNDEFINED_EVENT_ID);

    test_queue = queueInit(TEST_QUEUE_SIZE);
    assert(test_queue != NULL);
    XcpStart(test_queue, false);

    const uint8_t connect[] = {CC_CONNECT, 0};
    assert(run_command(connect, sizeof(connect)) == CRC_CMD_OK);

    test_daq_allocation_rollback();
    test_odt_allocation_rollback();
    test_odt_entry_allocation_rollback();
    test_odt_size_rollback(event);
    test_shared_event_daq_list(event);

    XcpDeinit();
    queueDeinit(test_queue);
    printf("DAQ configuration tests passed\n");
    return 0;
}
