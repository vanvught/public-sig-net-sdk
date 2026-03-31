//==============================================================================
// Sig-Net Protocol Framework - Type Definitions
//==============================================================================
//
// Copyright (c) 2026 Singularity (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//==============================================================================
// Author:       Wayne Howell
// Date:         March 28, 2026
// Prot Version: v0.12
// Description:  Data structures and type definitions including CoAP headers,
//               TLV structures, packet buffers, and receiver state tracking.
//               Used throughout the Sig-Net implementation.
//==============================================================================

#ifndef SIGNET_TYPES_HPP
#define SIGNET_TYPES_HPP

#include "sig-net-constants.hpp"
#include <stdint.h>
#include <string.h>

namespace SigNet {

//------------------------------------------------------------------------------
// CoAP Header Structure (RFC 7252 Section 3)
// 
// Packed 4-byte structure:
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Ver| T |  TKL  |      Code     |          Message ID           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//------------------------------------------------------------------------------

#pragma pack(push, 1)
struct CoAPHeader {
    uint8_t  version_type_tkl;  // Ver(2) | Type(2) | TKL(4)
    uint8_t  code;              // Request/Response code
    uint16_t message_id;        // Message ID (network byte order)
    
    // Helper methods for bit field access
    inline uint8_t GetVersion() const { return (version_type_tkl >> 6) & 0x03; }
    inline uint8_t GetType() const { return (version_type_tkl >> 4) & 0x03; }
    inline uint8_t GetTokenLength() const { return version_type_tkl & 0x0F; }
    
    inline void SetVersion(uint8_t ver) {
        version_type_tkl = (version_type_tkl & 0x3F) | ((ver & 0x03) << 6);
    }
    
    inline void SetType(uint8_t type) {
        version_type_tkl = (version_type_tkl & 0xCF) | ((type & 0x03) << 4);
    }
    
    inline void SetTokenLength(uint8_t tkl) {
        version_type_tkl = (version_type_tkl & 0xF0) | (tkl & 0x0F);
    }
};
#pragma pack(pop)

//------------------------------------------------------------------------------
// TLV (Type-Length-Value) Block Structure
// 
// Type:   2 bytes (network byte order)
// Length: 2 bytes (network byte order)
// Value:  Variable length data
//------------------------------------------------------------------------------

struct TLVBlock {
    uint16_t type_id;   // TID value (e.g., TID_LEVEL, TID_PRIORITY)
    uint16_t length;    // Length of value data in bytes
    const uint8_t* value;  // Pointer to value data (not owned by this struct)
    
    TLVBlock() : type_id(0), length(0), value(0) {}
    
    TLVBlock(uint16_t tid, uint16_t len, const uint8_t* val)
        : type_id(tid), length(len), value(val) {}
};

//------------------------------------------------------------------------------
// SigNet Custom Option Values
// 
// This structure holds the values for all six SigNet custom CoAP options
// that will be encoded into the packet.
//------------------------------------------------------------------------------

struct SigNetOptions {
    uint8_t  security_mode;              // SIGNET_OPTION_SECURITY_MODE (1 byte)
    uint8_t  sender_id[SENDER_ID_LENGTH]; // SIGNET_OPTION_SENDER_ID (8 bytes: TUID+endpoint)
    uint16_t mfg_code;                   // SIGNET_OPTION_MFG_CODE (2 bytes)
    uint32_t session_id;                 // SIGNET_OPTION_SESSION_ID (4 bytes)
    uint32_t seq_num;                    // SIGNET_OPTION_SEQ_NUM (4 bytes)
    uint8_t  hmac[HMAC_SHA256_LENGTH];   // SIGNET_OPTION_HMAC (32 bytes)
    
    SigNetOptions() : security_mode(0), mfg_code(0), session_id(0), seq_num(0) {
        memset(sender_id, 0, SENDER_ID_LENGTH);
        memset(hmac, 0, HMAC_SHA256_LENGTH);
    }
};

//------------------------------------------------------------------------------
// Packet Buffer Class
// 
// Manages a static 1400-byte buffer for constructing SigNet packets.
// Provides bounds-checking to prevent buffer overflows.
//------------------------------------------------------------------------------

class PacketBuffer {
public:
    PacketBuffer() : write_position_(0) {
        memset(buffer_, 0, MAX_UDP_PAYLOAD);
    }
    
    // Reset buffer for new packet construction
    void Reset() {
        write_position_ = 0;
        memset(buffer_, 0, MAX_UDP_PAYLOAD);
    }
    
    // Get current write position
    uint16_t GetPosition() const {
        return write_position_;
    }
    
    // Get total size of data written
    uint16_t GetSize() const {
        return write_position_;
    }
    
    // Get direct access to buffer (read-only)
    const uint8_t* GetBuffer() const {
        return buffer_;
    }
    
    // Get direct access to buffer (mutable) - use with caution
    uint8_t* GetMutableBuffer() {
        return buffer_;
    }
    
    // Check if there's enough space for 'size' bytes
    bool HasSpace(uint16_t size) const {
        return (write_position_ + size) <= MAX_UDP_PAYLOAD;
    }
    
    // Write a single byte
    int32_t WriteByte(uint8_t value) {
        if (!HasSpace(1)) {
            return SIGNET_ERROR_BUFFER_FULL;
        }
        buffer_[write_position_++] = value;
        return SIGNET_SUCCESS;
    }
    
    // Write multiple bytes
    int32_t WriteBytes(const uint8_t* data, uint16_t length) {
        if (!HasSpace(length)) {
            return SIGNET_ERROR_BUFFER_FULL;
        }
        memcpy(&buffer_[write_position_], data, length);
        write_position_ += length;
        return SIGNET_SUCCESS;
    }
    
    // Write a uint16_t in network byte order (big-endian)
    int32_t WriteUInt16(uint16_t value) {
        if (!HasSpace(2)) {
            return SIGNET_ERROR_BUFFER_FULL;
        }
        buffer_[write_position_++] = static_cast<uint8_t>(value >> 8);
        buffer_[write_position_++] = static_cast<uint8_t>(value & 0xFF);
        return SIGNET_SUCCESS;
    }
    
    // Write a uint32_t in network byte order (big-endian)
    int32_t WriteUInt32(uint32_t value) {
        if (!HasSpace(4)) {
            return SIGNET_ERROR_BUFFER_FULL;
        }
        buffer_[write_position_++] = static_cast<uint8_t>((value >> 24) & 0xFF);
        buffer_[write_position_++] = static_cast<uint8_t>((value >> 16) & 0xFF);
        buffer_[write_position_++] = static_cast<uint8_t>((value >> 8) & 0xFF);
        buffer_[write_position_++] = static_cast<uint8_t>(value & 0xFF);
        return SIGNET_SUCCESS;
    }
    
    // Seek to specific position (use with caution)
    int32_t Seek(uint16_t position) {
        if (position > MAX_UDP_PAYLOAD) {
            return SIGNET_ERROR_INVALID_ARG;
        }
        write_position_ = position;
        return SIGNET_SUCCESS;
    }
    
private:
    uint8_t  buffer_[MAX_UDP_PAYLOAD];  // Static 1400-byte buffer
    uint16_t write_position_;           // Current write position
};

//------------------------------------------------------------------------------
// Receiver Sender State
// 
// Tracks session/sequence state per unique Sender-ID (TUID+endpoint)
// for anti-replay protection per Section 8.6 Step 9.
//------------------------------------------------------------------------------

struct ReceiverSenderState {
    uint8_t  sender_id[SENDER_ID_LENGTH]; // TUID(6) + endpoint(2)
    uint32_t session_id;                  // Most recent valid session ID
    uint32_t seq_num;                     // Most recent valid sequence number
    uint32_t last_packet_time_ms;         // Timestamp of last accepted packet
    uint32_t total_packets_received;      // Total packets from this sender
    uint32_t total_packets_accepted;      // Total packets accepted (HMAC OK + fresh)
    
    ReceiverSenderState() : session_id(0), seq_num(0), last_packet_time_ms(0),
                           total_packets_received(0), total_packets_accepted(0) {
        memset(sender_id, 0, SENDER_ID_LENGTH);
    }
};

//------------------------------------------------------------------------------
// Receiver Statistics
// 
// Global receiver statistics for diagnostics.
//------------------------------------------------------------------------------

struct ReceiverStatistics {
    // Packet counts
    uint32_t total_packets;           // Total UDP packets received
    uint32_t accepted_packets;        // Packets accepted (all validation passed)
    
    // Rejection reasons
    uint32_t coap_version_errors;     // CoAP version != 1
    uint32_t coap_type_errors;        // CoAP type != NON (0)
    uint32_t coap_code_errors;        // CoAP code != POST (0.02)
    uint32_t uri_mismatches;          // URI not "/level/"
    uint32_t missing_options;         // Required options missing
    uint32_t hmac_failures;           // HMAC verification failed
    uint32_t replay_detected;         // Session/Sequence replay
    uint32_t parse_errors;            // Malformed packet structure
    
    // Timing
    uint32_t last_packet_time_ms;     // Timestamp of last packet
    
    ReceiverStatistics() : total_packets(0), accepted_packets(0),
                          coap_version_errors(0), coap_type_errors(0),
                          coap_code_errors(0), uri_mismatches(0),
                          missing_options(0), hmac_failures(0),
                          replay_detected(0), parse_errors(0),
                          last_packet_time_ms(0) {}
    
    void Reset() {
        total_packets = 0;
        accepted_packets = 0;
        coap_version_errors = 0;
        coap_type_errors = 0;
        coap_code_errors = 0;
        uri_mismatches = 0;
        missing_options = 0;
        hmac_failures = 0;
        replay_detected = 0;
        parse_errors = 0;
        last_packet_time_ms = 0;
    }
};

//------------------------------------------------------------------------------
// Received Packet Info
// 
// Information about a received packet for logging and diagnostics.
//------------------------------------------------------------------------------

struct ReceivedPacketInfo {
    // CoAP fields
    uint16_t message_id;              // CoAP Message ID
    
    // SigNet fields
    uint8_t  sender_tuid[6];          // Sender TUID (first 6 bytes of Sender-ID)
    uint16_t endpoint;                // Endpoint (last 2 bytes of Sender-ID)
    uint16_t mfg_code;                // Manufacturer code
    uint32_t session_id;              // Session ID
    uint32_t seq_num;                 // Sequence number
    
    // Payload info
    uint16_t dmx_slot_count;          // Number of DMX slots received
    
    // Validation results
    bool     hmac_valid;              // HMAC verification passed
    bool     session_fresh;           // Session/Sequence is fresh (not replay)
    
    // Rejection reason (if rejected)
    const char* rejection_reason;     // NULL if accepted, else description
    
    // Timing
    uint32_t timestamp_ms;            // Packet receive timestamp
    
    ReceivedPacketInfo() : message_id(0), endpoint(0), mfg_code(0),
                          session_id(0), seq_num(0), dmx_slot_count(0),
                          hmac_valid(false), session_fresh(false),
                          rejection_reason(0), timestamp_ms(0) {
        memset(sender_tuid, 0, 6);
    }
};

} // namespace SigNet

#endif // SIGNET_TYPES_HPP
