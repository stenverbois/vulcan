#include "sm_eval.h"
#include "../../drivers/mcp2515.h"
#include <sancus_support/sm_io.h>

#ifndef __SANCUS_IO_BENCH
    #warning benchmarking with debug print statements..
#endif

DECLARE_SM(sm_eval, 0x1234);

/*
 * Securely store connection initialization info in SM text section
 * NOTE: key secrecy is only protected via confidential loading during
 * the attestation process
 */
#if ATTESTATION
VULCAN_DATA uint8_t eval_key_aec_own[SANCUS_KEY_SIZE] = { 0x00 };
VULCAN_DATA uint8_t eval_key_aec_listen[SANCUS_KEY_SIZE] = { 0x00 };
VULCAN_DATA uint8_t eval_key_ping[SANCUS_KEY_SIZE] = { 0x00 };
VULCAN_DATA uint8_t eval_key_pong[SANCUS_KEY_SIZE] = { 0x00 };
#else
VULCAN_DATA const uint8_t eval_key_aec_own[SANCUS_KEY_SIZE] =
         {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
          0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
VULCAN_DATA const uint8_t eval_key_aec_listen[SANCUS_KEY_SIZE] =
         {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
          0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
VULCAN_DATA const uint8_t eval_key_ping[SANCUS_KEY_SIZE] =
         {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
          0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
VULCAN_DATA const uint8_t eval_key_pong[SANCUS_KEY_SIZE] =
         {0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
          0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
#endif

/*
 * Securely store the state of this SM
 *
 * 0 - Attestation phase. SM will accept key distribution messages from the
 *     attestation server.
 * 1 - Authenticated communication phase. SM uses its session keys and no
 *     longer accepts new ones.
 */
VULCAN_DATA int eval_state = 0;
VULCAN_DATA ican_link_info_t eval_connections[EVAL_NB_CONNECTIONS];

// Untrusted key sequence receive buffer
#define SEQUENCE_LEN (2 + 2 * SANCUS_SECURITY_BYTES / 8)
key_sequence_t u_key_sequence_recv;

void request_key_unprotected(uint16_t send, uint16_t recv)
{
    // Send key request to the attestation server
    ican_buf_t request = {0x00};
    request.words[0] = send;
    request.words[1] = recv;
    ican_send(&msp_ican, CAN_ID_ATTEST_RECV, request.bytes, /*len=*/4, /*block=*/1);

    pr_info2("Sent key request for %X-%X\n", send, recv); 
}

void receive_key_sequence_unprotected()
{
    int i;
    uint16_t id = 0;
    // Receive response consisting of 6 CAN messages:
    // id_sm, id_connection (1 msg), nonce (1 msg), key (2 msg) and mac over all previous messages (2 msg)
    for(i = 0; i < SEQUENCE_LEN; i++) {
        ican_recv(&msp_ican, &id, (uint8_t*)(&u_key_sequence_recv) + i * CAN_PAYLOAD_SIZE, /*block=*/1);
        pr_debug_buf((uint8_t*)(&u_key_sequence_recv) + i * CAN_PAYLOAD_SIZE, CAN_PAYLOAD_SIZE, INFO_STR("RECEIVED: "));
    }
}

/*
 * Unwraps key sequence `cipher` into `unwrapped`.
 */
int VULCAN_FUNC unwrap_key_sequence(key_sequence_t* cipher, key_sequence_t* unwrapped)
{
    const size_t AD_LEN = 4;
    uint8_t ad[AD_LEN] = {0x01, 0x02, 0x03, 0x04};

    return sancus_unwrap(ad, AD_LEN, (uint8_t*)cipher, sizeof(key_sequence_t) - SANCUS_SECURITY_BYTES, cipher->mac, (uint8_t*)unwrapped);
}

/*
 * Receives a key sequence from the CAN bus.
 * Returns true if unwrapping succeeded, false otherwise.
 */
int VULCAN_FUNC receive_key_sequence(key_sequence_t* unwrapped)
{
    int res = 0;

    receive_key_sequence_unprotected();
    res = unwrap_key_sequence(&u_key_sequence_recv, unwrapped);

    pr_info1("Unwrapping result: %i\n", res);

    pr_debug_buf((uint8_t*)unwrapped, CAN_PAYLOAD_SIZE, INFO_STR("Received id: "));
    pr_debug_buf((uint8_t*)unwrapped + CAN_PAYLOAD_SIZE, CAN_PAYLOAD_SIZE, INFO_STR("Received nonce: "));
    pr_debug_buf((uint8_t*)unwrapped + CAN_PAYLOAD_SIZE * 2, CAN_PAYLOAD_SIZE * 2, INFO_STR("Received key: "));

    return res;
}

/*
 * Returns a pointer to the ican_link_info_t with the given id,
 * or NULL if none is found.
 */
ican_link_info_t* VULCAN_FUNC eval_find_connection(uint16_t id)
{
    int i;

    for (i = 0; i < EVAL_NB_CONNECTIONS; i++)
    {
        if (eval_connections[i].id == id)
        {
            return &eval_connections[i];
        }
    }

    return NULL;
}

/*
 * Returns true if all connections have the CONNECTION_INITIALIZED flag set,
 * and false otherwise.
 */
int VULCAN_FUNC eval_all_connections_initialized()
{
    int i;
    for (i = 0; i < EVAL_NB_CONNECTIONS; i++)
    {
        if (!(eval_connections[i].flags & CONNECTION_INITIALIZED))
        {
            return 0;
        }
    }

    return 1;
}

/*
 * Copy a connection key.
 */
void VULCAN_FUNC eval_copy_key(uint8_t* dst, const uint8_t* src)
{
    int i;
    for (i = 0; i < 16; i++)
    {
        dst[i] = src[i];
    }
}

#ifndef CAN_DRV_SM
    uint8_t u_msg_buf[CAN_PAYLOAD_SIZE];
    uint16_t u_id;

    int __attribute__((noinline)) u_can_send(ican_t* ican, uint16_t id,
                                             uint8_t len, int block)
    {
        pr_debug_buf(u_msg_buf, len, INFO_STR("u_can_send buffer"));
        int rv;
        while ((rv = ican_send(ican, id, u_msg_buf, len, block)) == -EAGAIN);
        return rv;
    }
#endif


int VULCAN_FUNC attest_respond(ican_t *ican, uint16_t id, uint8_t *buf,
                          uint8_t len, int block)
{
    int i, rv;

    #if defined(VULCAN_SM) && !defined(CAN_DRV_SM)
        for (i = 0; i < len; i++)
            u_msg_buf[i] = buf[i];
        return u_can_send(ican, id, len, block);
    #else
        while ((rv = ican_send(ican, id, buf, len, block)) == -EAGAIN);
        return rv;
    #endif
}

void VULCAN_FUNC eval_do_attestation(uint16_t id_sm)
{
    int unwrap_result;
    uint16_t connection_id;
    key_sequence_t unwrapped_sequence;
    ican_link_info_t* conn_cur;
    ican_tag_t tag;

    while (!eval_all_connections_initialized())
    {
        unwrap_result = receive_key_sequence(&unwrapped_sequence);
        
        // If unwrapping was unsuccessful, this key sequence was not meant for this SM
        if (!unwrap_result)
            continue;

        connection_id = unwrapped_sequence.connection_id;
        conn_cur = eval_find_connection(connection_id);
        if (conn_cur)
        {
            eval_copy_key(conn_cur->k_i, unwrapped_sequence.connection_key);
            conn_cur->flags |= CONNECTION_INITIALIZED;
            
            pr_info1("Initialized: %X\n", connection_id);
            
            sancus_tag(unwrapped_sequence.nonce, 8, tag.bytes);
            ican_buf_t b;
            b.quad = 0;
            b.words[0] = id_sm;
            b.words[1] = connection_id;
            attest_respond(&msp_ican, CAN_ID_ATTEST_RECV, b.bytes, CAN_PAYLOAD_SIZE, /*block=*/1);
            attest_respond(&msp_ican, CAN_ID_ATTEST_RECV, (uint8_t*)(&tag.quads[1]), CAN_PAYLOAD_SIZE, /*block=*/1);
        }
    }

    pr_progress("All connections initialized");
}

void VULCAN_FUNC eval_do_init(uint16_t id_sm, uint16_t aec_own, uint16_t aec_listen)
{
    int i;

    if (eval_state) return;

    eval_connections[0].id = CAN_ID_PING;
    eval_connections[0].k_i = &eval_key_ping[0];
    eval_connections[0].flags = 0;
    eval_connections[1].id = CAN_ID_PONG;
    eval_connections[1].k_i = &eval_key_pong[0];
    eval_connections[1].flags = 0;
    eval_connections[2].id = aec_listen;
    eval_connections[2].k_i = &eval_key_aec_listen[0];
    eval_connections[2].flags = 0;
    eval_connections[3].id = aec_own;
    eval_connections[3].k_i = &eval_key_aec_own[0];
    eval_connections[3].flags = 0;

    i = ican_init(&msp_ican);
    ASSERT(i >= 0);
    pr_info("CAN controller initialized");

    #if ATTESTATION
        eval_do_attestation(id_sm);

        pr_debug_buf(eval_connections[0].k_i, 16, INFO_STR("conn F0 k_i"));
        pr_debug_buf(eval_connections[1].k_i, 16, INFO_STR("conn F1 k_i"));
    #endif

    vulcan_init(&msp_ican, eval_connections, EVAL_NB_CONNECTIONS);
    
    // Transition to authenticated communication state
    eval_state = 1;
}

void SM_ENTRY(sm_eval) dummy_entry(void)
{
    return;
}
