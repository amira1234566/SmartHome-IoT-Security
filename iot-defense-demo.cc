/* ============================================================================
 *  iot-defense-demo.cc -- FINAL GRADUATION DEFENSE VERSION
 *  Secure Smart Home IoT: LDAP + LDAP Cache + RADIUS (+Accounting) +
 *  IEEE 802.1X + Kerberos + Gateway (Ticket/MAC/Replay/RBAC), with Replay
 *  Attack and Privilege Escalation attack/protection.
 *  Companion to the full iot-baseline.cc (unchanged), trimmed for study.
 * ----------------------------------------------------------------------------
 *  CODE DEFENSE INDEX -- search the exact "SHOW: ..." label to jump to the
 *  primary implementation of each feature. Each label appears exactly once.
 *
 *    SHOW: IEEE 802.1X – AUTHENTICATOR             -> Dot1xAuthenticatorApp
 *    SHOW: EAPOL – REQUEST                         -> SmartHomeUserApp::SendEapolRequest
 *    SHOW: RADIUS – AUTHENTICATION                 -> RadiusServerApp::ReceiveAuth
 *    SHOW: RADIUS – ACCOUNTING                     -> RadiusServerApp::ReceiveAcct
 *    SHOW: LDAP – LOOKUP                           -> LdapServerApp::ReceiveQuery
 *    SHOW: LDAP CACHE – HIT AND MISS                -> RadiusServerApp::ReceiveAuth (cache branch)
 *    SHOW: KERBEROS – TICKET ISSUING                -> KdcApp::IssueKerberosTicket
 *    SHOW: KERBEROS – TICKET VALIDATION             -> SmartHomeGatewayApp::ValidateTicket
 *    SHOW: COMMAND MAC – GENERATION                 -> CalculateCommandMac
 *    SHOW: COMMAND MAC – VERIFICATION               -> SmartHomeGatewayApp::ValidateCommandMac
 *    SHOW: SEQUENCE NUMBER – GENERATION             -> SmartHomeUserApp::CreateCommandPacket
 *    SHOW: REPLAY ATTACK – PACKET CAPTURE           -> SmartHomeGatewayApp::CaptureLegitimateReplayPacket
 *    SHOW: REPLAY ATTACK – PACKET RESEND            -> ReplayAttackApp::TrySendReplay
 *    SHOW: ANTI-REPLAY – DUPLICATE DETECTION        -> SmartHomeGatewayApp::DetectReplay
 *    SHOW: RBAC – PERMISSION CHECK                  -> SmartHomeGatewayApp::ValidatePermission
 *    SHOW: PRIVILEGE ESCALATION – FORGED CLAIMS     -> SmartHomeUserApp::CreatePrivilegeEscalationAttempt
 *    SHOW: PRIVILEGE ESCALATION – DETECTION AND BLOCKING -> SmartHomeGatewayApp::ValidateCommandMac
 *    SHOW: GATEWAY – SECURITY PIPELINE              -> SmartHomeGatewayApp::ProcessGatewayCommand
 *    SHOW: FINAL RESULTS                            -> PrintResults
 * ========================================================================== */

// ================================ SECTION 1: CONFIGURATION AND IDENTITIES ==
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/csma-module.h"
#include "ns3/applications-module.h"
#include <iostream>
#include <map>
#include <set>
#include <vector>
#include <string>
#include <cstring>
#include <utility>

using namespace ns3;

static const uint16_t RADIUS_PORT   = 1812;
static const uint16_t RADIUS_ACCT_PORT = 1813;
static const uint16_t LDAP_PORT     = 3890;
static const uint16_t KDC_PORT      = 8888;
static const uint16_t GATEWAY_PORT  = 9000;
static const uint16_t DEVICE_PORT   = 9100;
static const uint16_t EAPOL_PORT    = 8880;

enum EapCode : uint8_t { EAP_RESPONSE = 1, EAP_SUCCESS = 2, EAP_FAILURE = 3 };
enum Dot1xState : uint8_t { DOT1X_UNAUTHORIZED = 0, DOT1X_AUTHORIZED = 1 };

static const uint32_t TICKET_MAGIC   = 0xAABBCCDD;
static const uint32_t RADIUS_SECRET  = 0x13572468;

static const uint8_t ROLE_OWNER = 0, ROLE_GUEST = 1, ROLE_MAINTENANCE = 2, ROLE_DISABLED = 3, ROLE_DEVICE = 4;
static const uint32_t PERM_TELEMETRY = 1<<0, PERM_DOOR = 1<<1, PERM_LIGHT = 1<<2, PERM_CAMERA = 1<<3, PERM_PLUG = 1<<4;

static const uint32_t USER_AHMAD = 100, USER_SARA = 101, USER_OMAR = 102, USER_LINA = 103;
static const uint32_t CACHE_PROBE_PID = 200; // isolated demo identity, never used by the main scenario
static const uint32_t DEV_TEMPERATURE = 1, DEV_MOTION = 2, DEV_DOOR = 3, DEV_LIGHT = 4, DEV_CAMERA = 5, DEV_PLUG = 6;

enum SmartHomeCommand : uint8_t
{
  CMD_SEND_TEMPERATURE = 1, CMD_SEND_MOTION = 2, CMD_OPEN_DOOR = 3,
  CMD_LIGHT_ON = 5, CMD_CAMERA_VIEW = 7, CMD_PLUG_ON = 9
};

static std::map<uint32_t, std::string> g_names;
static std::string PrincipalName(uint32_t id)
{ auto it = g_names.find(id); return it == g_names.end() ? "Unknown" : it->second; }
static std::string RoleName(uint8_t r)
{
  switch (r) { case ROLE_OWNER: return "OWNER"; case ROLE_GUEST: return "GUEST";
    case ROLE_MAINTENANCE: return "MAINTENANCE"; case ROLE_DISABLED: return "DISABLED";
    case ROLE_DEVICE: return "DEVICE"; default: return "UNKNOWN"; }
}
static std::string CommandName(uint8_t c)
{
  switch (c) { case CMD_SEND_TEMPERATURE: return "SEND_TEMPERATURE"; case CMD_SEND_MOTION: return "SEND_MOTION";
    case CMD_OPEN_DOOR: return "OPEN_DOOR"; case CMD_LIGHT_ON: return "LIGHT_ON";
    case CMD_CAMERA_VIEW: return "CAMERA_VIEW"; case CMD_PLUG_ON: return "PLUG_ON"; default: return "NONE"; }
}
static uint32_t RequiredPermission(uint8_t c)
{
  switch (c) { case CMD_SEND_TEMPERATURE: case CMD_SEND_MOTION: return PERM_TELEMETRY;
    case CMD_OPEN_DOOR: return PERM_DOOR; case CMD_LIGHT_ON: return PERM_LIGHT;
    case CMD_CAMERA_VIEW: return PERM_CAMERA;
    case CMD_PLUG_ON: return PERM_PLUG; default: return 0xFFFFFFFFu; }
}
static std::string PermissionName(uint32_t perm)
{
  switch (perm) { case PERM_TELEMETRY: return "TELEMETRY"; case PERM_DOOR: return "DOOR";
    case PERM_LIGHT: return "LIGHT"; case PERM_CAMERA: return "CAMERA";
    case PERM_PLUG: return "PLUG"; default: return "UNKNOWN"; }
}
static uint32_t TargetDeviceForCommand(uint8_t c)
{
  switch (c) { case CMD_OPEN_DOOR: return DEV_DOOR; case CMD_LIGHT_ON: return DEV_LIGHT;
    case CMD_CAMERA_VIEW: return DEV_CAMERA; case CMD_PLUG_ON: return DEV_PLUG; default: return 0; }
}

struct UserProfile { uint32_t principalId=0; uint32_t passwordSecret=0; uint32_t salt=0; };
struct LdapEntry
{
  uint8_t role=ROLE_DISABLED; bool enabled=false;
  uint32_t permissionMask=0; uint32_t passwordHash=0;
};

// Global result counters -- printed once at the end by PrintResults (SECTION 10).
struct Results
{
  uint64_t authAccepted=0, authRejected=0, ticketsIssued=0;
  uint64_t commandsAccepted=0, commandsRejected=0;
  uint64_t dropBadCommandMac=0, dropUnauthorizedPermission=0;
  uint64_t dot1xAuthorized=0, dot1xUnauthorized=0;
  uint64_t replayAttempts=0, replayDetected=0, replayAccepted=0, dropReplay=0;
  uint64_t privilegeEscalationAttempts=0, privilegeEscalationDetected=0;
  uint64_t privilegeEscalationAccepted=0, dropPrivilegeEscalation=0;
  uint64_t cacheHits=0, cacheMisses=0;
  uint64_t totalAuthRequests=0, ldapQueries=0;
  uint64_t acctStarts=0, acctStops=0;
};
static Results g_res;
static const char *LINE_THIN  = "------------------------------------------------------------";
static const char *LINE_THICK = "============================================================";
static uint32_t g_cacheProbeTotal = 0; // total probes in the LDAP Cache demo, set once by InstallCacheProbe
static Ptr<Packet> g_capturedOpenDoorPacket = nullptr;
static bool g_enablePrivilegeEscalationAttack = false;
static bool g_enablePrivilegeEscalationProtection = true;
static bool g_showAuthenticationFlow = true; // --showAuthenticationFlow: console detail only, never affects logic

// ===================================== SECTION 2: PACKET HEADERS ==========
// ---- EAP ----
class EapHeader : public Header
{
public:
  EapHeader() : m_code(0), m_type(0), m_principalId(0), m_nonce(0), m_credProof(0), m_sessionId(0) {}
  EapHeader(uint8_t code, uint8_t type, uint32_t pid, uint32_t nonce, uint32_t credProof, uint32_t sid)
    : m_code(code), m_type(type), m_principalId(pid), m_nonce(nonce), m_credProof(credProof), m_sessionId(sid) {}
  static TypeId GetTypeId() { static TypeId t = TypeId("EapHeader").SetParent<Header>().AddConstructor<EapHeader>(); return t; }
  TypeId GetInstanceTypeId() const override { return GetTypeId(); }
  uint32_t GetSerializedSize() const override { return 1+1+2+4+4+4+4; }
  void Serialize(Buffer::Iterator i) const override
  { i.WriteU8(m_code); i.WriteU8(m_type); i.WriteU8(0); i.WriteU8(0);
    i.WriteHtonU32(m_principalId); i.WriteHtonU32(m_nonce); i.WriteHtonU32(m_credProof); i.WriteHtonU32(m_sessionId); }
  uint32_t Deserialize(Buffer::Iterator i) override
  { m_code=i.ReadU8(); m_type=i.ReadU8(); i.ReadU8(); i.ReadU8();
    m_principalId=i.ReadNtohU32(); m_nonce=i.ReadNtohU32(); m_credProof=i.ReadNtohU32(); m_sessionId=i.ReadNtohU32();
    return GetSerializedSize(); }
  void Print(std::ostream &os) const override { os << "EAP code=" << unsigned(m_code); }
  uint8_t GetCode() const { return m_code; }
  uint32_t GetPrincipalId() const { return m_principalId; }
  uint32_t GetNonce() const { return m_nonce; }
  uint32_t GetCredProof() const { return m_credProof; }
  uint32_t GetSessionId() const { return m_sessionId; }
private:
  uint8_t m_code, m_type; uint32_t m_principalId, m_nonce, m_credProof, m_sessionId;
};

// ---- EAPOL (carries EAP, Supplicant <-> Authenticator only) ----
class EapolHeader : public Header
{
public:
  EapolHeader() : m_version(1) {}
  static TypeId GetTypeId() { static TypeId t = TypeId("EapolHeader").SetParent<Header>().AddConstructor<EapolHeader>(); return t; }
  TypeId GetInstanceTypeId() const override { return GetTypeId(); }
  uint32_t GetSerializedSize() const override { return 1; }
  void Serialize(Buffer::Iterator i) const override { i.WriteU8(m_version); }
  uint32_t Deserialize(Buffer::Iterator i) override { m_version=i.ReadU8(); return GetSerializedSize(); }
  void Print(std::ostream &os) const override { os << "EAPOL"; }
private:
  uint8_t m_version;
};

// ---- RADIUS ----
class RadiusAuthHeader : public Header
{
public:
  RadiusAuthHeader() : m_principalId(0), m_nonce(0), m_auth(0), m_credProof(0) {}
  RadiusAuthHeader(uint32_t pid, uint32_t nonce, uint32_t auth, uint32_t credProof)
    : m_principalId(pid), m_nonce(nonce), m_auth(auth), m_credProof(credProof) {}
  static TypeId GetTypeId() { static TypeId t = TypeId("RadiusAuthHeader").SetParent<Header>().AddConstructor<RadiusAuthHeader>(); return t; }
  TypeId GetInstanceTypeId() const override { return GetTypeId(); }
  uint32_t GetSerializedSize() const override { return 16; }
  void Serialize(Buffer::Iterator i) const override
  { i.WriteHtonU32(m_principalId); i.WriteHtonU32(m_nonce); i.WriteHtonU32(m_auth); i.WriteHtonU32(m_credProof); }
  uint32_t Deserialize(Buffer::Iterator i) override
  { m_principalId=i.ReadNtohU32(); m_nonce=i.ReadNtohU32(); m_auth=i.ReadNtohU32(); m_credProof=i.ReadNtohU32(); return GetSerializedSize(); }
  void Print(std::ostream &os) const override { os << "RadiusAuth principalId=" << m_principalId; }
  uint32_t GetPrincipalId() const { return m_principalId; }
  uint32_t GetNonce() const { return m_nonce; }
  uint32_t GetAuth() const { return m_auth; }
  uint32_t GetCredProof() const { return m_credProof; }
private:
  uint32_t m_principalId, m_nonce, m_auth, m_credProof;
};

class RadiusReplyHeader : public Header
{
public:
  RadiusReplyHeader() : m_principalId(0), m_accept(0), m_sessionId(0) {}
  RadiusReplyHeader(uint32_t pid, uint8_t accept, uint32_t sid) : m_principalId(pid), m_accept(accept), m_sessionId(sid) {}
  static TypeId GetTypeId() { static TypeId t = TypeId("RadiusReplyHeader").SetParent<Header>().AddConstructor<RadiusReplyHeader>(); return t; }
  TypeId GetInstanceTypeId() const override { return GetTypeId(); }
  uint32_t GetSerializedSize() const override { return 9; }
  void Serialize(Buffer::Iterator i) const override
  { i.WriteHtonU32(m_principalId); i.WriteU8(m_accept); i.WriteHtonU32(m_sessionId); }
  uint32_t Deserialize(Buffer::Iterator i) override
  { m_principalId=i.ReadNtohU32(); m_accept=i.ReadU8(); m_sessionId=i.ReadNtohU32(); return GetSerializedSize(); }
  void Print(std::ostream &os) const override { os << "RadiusReply accept=" << unsigned(m_accept); }
  uint32_t GetPrincipalId() const { return m_principalId; }
  bool IsAccept() const { return m_accept != 0; }
  uint32_t GetSessionId() const { return m_sessionId; }
private:
  uint32_t m_principalId; uint8_t m_accept; uint32_t m_sessionId;
};

// ---- LDAP ----
// LdapQueryHeader carries a requestId so RadiusServerApp can correlate the
// reply safely (never relies on receive order).
class LdapQueryHeader : public Header
{
public:
  LdapQueryHeader() : m_reqId(0), m_principalId(0), m_credNonce(0), m_credProof(0) {}
  LdapQueryHeader(uint32_t reqId, uint32_t pid, uint32_t credNonce, uint32_t credProof)
    : m_reqId(reqId), m_principalId(pid), m_credNonce(credNonce), m_credProof(credProof) {}
  static TypeId GetTypeId() { static TypeId t = TypeId("LdapQueryHeader").SetParent<Header>().AddConstructor<LdapQueryHeader>(); return t; }
  TypeId GetInstanceTypeId() const override { return GetTypeId(); }
  uint32_t GetSerializedSize() const override { return 16; }
  void Serialize(Buffer::Iterator i) const override
  { i.WriteHtonU32(m_reqId); i.WriteHtonU32(m_principalId); i.WriteHtonU32(m_credNonce); i.WriteHtonU32(m_credProof); }
  uint32_t Deserialize(Buffer::Iterator i) override
  { m_reqId=i.ReadNtohU32(); m_principalId=i.ReadNtohU32(); m_credNonce=i.ReadNtohU32(); m_credProof=i.ReadNtohU32(); return GetSerializedSize(); }
  void Print(std::ostream &os) const override { os << "LdapQuery principalId=" << m_principalId; }
  uint32_t GetReqId() const { return m_reqId; }
  uint32_t GetPrincipalId() const { return m_principalId; }
  uint32_t GetCredNonce() const { return m_credNonce; }
  uint32_t GetCredProof() const { return m_credProof; }
private:
  uint32_t m_reqId, m_principalId, m_credNonce, m_credProof;
};

class LdapReplyHeader : public Header
{
public:
  LdapReplyHeader() : m_reqId(0), m_principalId(0), m_valid(0), m_enabled(0), m_credOk(0), m_role(0), m_perm(0), m_pwHash(0) {}
  LdapReplyHeader(uint32_t reqId, uint32_t pid, uint8_t valid, uint8_t enabled, uint8_t credOk,
                   uint8_t role, uint32_t perm, uint32_t pwHash)
    : m_reqId(reqId), m_principalId(pid), m_valid(valid), m_enabled(enabled), m_credOk(credOk),
      m_role(role), m_perm(perm), m_pwHash(pwHash) {}
  static TypeId GetTypeId() { static TypeId t = TypeId("LdapReplyHeader").SetParent<Header>().AddConstructor<LdapReplyHeader>(); return t; }
  TypeId GetInstanceTypeId() const override { return GetTypeId(); }
  uint32_t GetSerializedSize() const override { return 4+4+1+1+1+1+4+4; }
  void Serialize(Buffer::Iterator i) const override
  { i.WriteHtonU32(m_reqId); i.WriteHtonU32(m_principalId); i.WriteU8(m_valid); i.WriteU8(m_enabled); i.WriteU8(m_credOk);
    i.WriteU8(m_role); i.WriteHtonU32(m_perm); i.WriteHtonU32(m_pwHash); }
  uint32_t Deserialize(Buffer::Iterator i) override
  { m_reqId=i.ReadNtohU32(); m_principalId=i.ReadNtohU32(); m_valid=i.ReadU8(); m_enabled=i.ReadU8(); m_credOk=i.ReadU8();
    m_role=i.ReadU8(); m_perm=i.ReadNtohU32(); m_pwHash=i.ReadNtohU32(); return GetSerializedSize(); }
  void Print(std::ostream &os) const override { os << "LdapReply principalId=" << m_principalId; }
  uint32_t GetReqId() const { return m_reqId; }
  uint32_t GetPrincipalId() const { return m_principalId; }
  bool IsValid() const { return m_valid; } bool IsEnabled() const { return m_enabled; } bool IsCredOk() const { return m_credOk; }
  uint8_t GetRole() const { return m_role; } uint32_t GetPerm() const { return m_perm; } uint32_t GetPasswordHash() const { return m_pwHash; }
private:
  uint32_t m_reqId, m_principalId; uint8_t m_valid, m_enabled, m_credOk, m_role; uint32_t m_perm, m_pwHash;
};

// RadiusAcctHeader: minimal RADIUS Accounting -- Start (type=1) / Stop (type=2).
class RadiusAcctHeader : public Header
{
public:
  RadiusAcctHeader() : m_principalId(0), m_type(0) {}
  RadiusAcctHeader(uint32_t pid, uint8_t type) : m_principalId(pid), m_type(type) {}
  static TypeId GetTypeId() { static TypeId t = TypeId("RadiusAcctHeader").SetParent<Header>().AddConstructor<RadiusAcctHeader>(); return t; }
  TypeId GetInstanceTypeId() const override { return GetTypeId(); }
  uint32_t GetSerializedSize() const override { return 5; }
  void Serialize(Buffer::Iterator i) const override { i.WriteHtonU32(m_principalId); i.WriteU8(m_type); }
  uint32_t Deserialize(Buffer::Iterator i) override { m_principalId=i.ReadNtohU32(); m_type=i.ReadU8(); return GetSerializedSize(); }
  void Print(std::ostream &os) const override { os << "RadiusAcct type=" << unsigned(m_type); }
  uint32_t GetPrincipalId() const { return m_principalId; }
  uint8_t GetType() const { return m_type; }
private:
  uint32_t m_principalId; uint8_t m_type;
};

// ---- Ticket ----
class TicketRequestHeader : public Header
{
public:
  TicketRequestHeader() : m_principalId(0), m_sessionId(0) {}
  TicketRequestHeader(uint32_t pid, uint32_t sid) : m_principalId(pid), m_sessionId(sid) {}
  static TypeId GetTypeId() { static TypeId t = TypeId("TicketRequestHeader").SetParent<Header>().AddConstructor<TicketRequestHeader>(); return t; }
  TypeId GetInstanceTypeId() const override { return GetTypeId(); }
  uint32_t GetSerializedSize() const override { return 8; }
  void Serialize(Buffer::Iterator i) const override { i.WriteHtonU32(m_principalId); i.WriteHtonU32(m_sessionId); }
  uint32_t Deserialize(Buffer::Iterator i) override { m_principalId=i.ReadNtohU32(); m_sessionId=i.ReadNtohU32(); return GetSerializedSize(); }
  void Print(std::ostream &os) const override { os << "TicketRequest principalId=" << m_principalId; }
  uint32_t GetPrincipalId() const { return m_principalId; }
  uint32_t GetSessionId() const { return m_sessionId; }
private:
  uint32_t m_principalId, m_sessionId;
};

class TicketResponseHeader : public Header
{
public:
  TicketResponseHeader() : m_magic(0), m_principalId(0), m_sessionId(0), m_sessionKey(0), m_expiryMs(0), m_perm(0), m_role(0) {}
  TicketResponseHeader(uint32_t magic, uint32_t pid, uint32_t sid, uint32_t key, uint32_t expiry, uint32_t perm, uint8_t role)
    : m_magic(magic), m_principalId(pid), m_sessionId(sid), m_sessionKey(key), m_expiryMs(expiry), m_perm(perm), m_role(role) {}
  static TypeId GetTypeId() { static TypeId t = TypeId("TicketResponseHeader").SetParent<Header>().AddConstructor<TicketResponseHeader>(); return t; }
  TypeId GetInstanceTypeId() const override { return GetTypeId(); }
  uint32_t GetSerializedSize() const override { return 4+4+4+4+4+4+1+3; }
  void Serialize(Buffer::Iterator i) const override
  { i.WriteHtonU32(m_magic); i.WriteHtonU32(m_principalId); i.WriteHtonU32(m_sessionId);
    i.WriteHtonU32(m_sessionKey); i.WriteHtonU32(m_expiryMs); i.WriteHtonU32(m_perm);
    i.WriteU8(m_role); i.WriteU8(0); i.WriteU8(0); i.WriteU8(0); }
  uint32_t Deserialize(Buffer::Iterator i) override
  { m_magic=i.ReadNtohU32(); m_principalId=i.ReadNtohU32(); m_sessionId=i.ReadNtohU32();
    m_sessionKey=i.ReadNtohU32(); m_expiryMs=i.ReadNtohU32(); m_perm=i.ReadNtohU32();
    m_role=i.ReadU8(); i.ReadU8(); i.ReadU8(); i.ReadU8(); return GetSerializedSize(); }
  void Print(std::ostream &os) const override { os << "Ticket principalId=" << m_principalId; }
  uint32_t GetMagic() const { return m_magic; }
  uint32_t GetPrincipalId() const { return m_principalId; }
  uint32_t GetSessionId() const { return m_sessionId; }
  uint32_t GetSessionKey() const { return m_sessionKey; }
  uint32_t GetExpiryMs() const { return m_expiryMs; }
  uint32_t GetPermissionMask() const { return m_perm; }
  uint8_t GetRoleId() const { return m_role; }
private:
  uint32_t m_magic, m_principalId, m_sessionId, m_sessionKey, m_expiryMs, m_perm; uint8_t m_role;
};

// ---- Command ----
// Carries role/permissionMask claims, protected by CalculateCommandMac.
class CommandRequestHeader : public Header
{
public:
  CommandRequestHeader() : m_principalId(0), m_deviceId(0), m_command(0), m_sentMs(0), m_mac(0), m_seq(0), m_role(0), m_perm(0) {}
  CommandRequestHeader(uint32_t pid, uint32_t dev, uint8_t cmd, uint32_t sentMs, uint32_t mac, uint32_t seq, uint8_t role, uint32_t perm)
    : m_principalId(pid), m_deviceId(dev), m_command(cmd), m_sentMs(sentMs), m_mac(mac), m_seq(seq), m_role(role), m_perm(perm) {}
  static TypeId GetTypeId() { static TypeId t = TypeId("CommandRequestHeader").SetParent<Header>().AddConstructor<CommandRequestHeader>(); return t; }
  TypeId GetInstanceTypeId() const override { return GetTypeId(); }
  uint32_t GetSerializedSize() const override { return 4+4+1+3+4+4+4+1+3+4; }
  void Serialize(Buffer::Iterator i) const override
  { i.WriteHtonU32(m_principalId); i.WriteHtonU32(m_deviceId); i.WriteU8(m_command); i.WriteU8(0); i.WriteU8(0); i.WriteU8(0);
    i.WriteHtonU32(m_sentMs); i.WriteHtonU32(m_mac); i.WriteHtonU32(m_seq);
    i.WriteU8(m_role); i.WriteU8(0); i.WriteU8(0); i.WriteU8(0); i.WriteHtonU32(m_perm); }
  uint32_t Deserialize(Buffer::Iterator i) override
  { m_principalId=i.ReadNtohU32(); m_deviceId=i.ReadNtohU32(); m_command=i.ReadU8(); i.ReadU8(); i.ReadU8(); i.ReadU8();
    m_sentMs=i.ReadNtohU32(); m_mac=i.ReadNtohU32(); m_seq=i.ReadNtohU32();
    m_role=i.ReadU8(); i.ReadU8(); i.ReadU8(); i.ReadU8(); m_perm=i.ReadNtohU32(); return GetSerializedSize(); }
  void Print(std::ostream &os) const override { os << "Command principalId=" << m_principalId << " cmd=" << unsigned(m_command); }
  uint32_t GetPrincipalId() const { return m_principalId; }
  uint32_t GetDeviceId() const { return m_deviceId; }
  uint8_t GetCommand() const { return m_command; }
  uint32_t GetSentMs() const { return m_sentMs; }
  uint32_t GetMac() const { return m_mac; }
  uint32_t GetSeq() const { return m_seq; }
  uint8_t GetRole() const { return m_role; }
  uint32_t GetPerm() const { return m_perm; }
private:
  uint32_t m_principalId, m_deviceId; uint8_t m_command; uint32_t m_sentMs, m_mac, m_seq; uint8_t m_role; uint32_t m_perm;
};

class ExecuteHeader : public Header
{
public:
  ExecuteHeader() : m_principalId(0), m_deviceId(0), m_command(0) {}
  ExecuteHeader(uint32_t pid, uint32_t dev, uint8_t cmd) : m_principalId(pid), m_deviceId(dev), m_command(cmd) {}
  static TypeId GetTypeId() { static TypeId t = TypeId("ExecuteHeader").SetParent<Header>().AddConstructor<ExecuteHeader>(); return t; }
  TypeId GetInstanceTypeId() const override { return GetTypeId(); }
  uint32_t GetSerializedSize() const override { return 9; }
  void Serialize(Buffer::Iterator i) const override { i.WriteHtonU32(m_principalId); i.WriteHtonU32(m_deviceId); i.WriteU8(m_command); }
  uint32_t Deserialize(Buffer::Iterator i) override
  { m_principalId=i.ReadNtohU32(); m_deviceId=i.ReadNtohU32(); m_command=i.ReadU8(); return GetSerializedSize(); }
  void Print(std::ostream &os) const override { os << "Execute cmd=" << unsigned(m_command); }
  uint8_t GetCommand() const { return m_command; }
private:
  uint32_t m_principalId, m_deviceId; uint8_t m_command;
};

// ================================== SECTION 3: SECURITY FUNCTIONS =========
// Lightweight modeling only (hash-like mixing), NOT real cryptography.
static uint32_t SimplePasswordHash(uint32_t secret, uint32_t salt)
{ uint32_t h=2166136261u; h^=salt; h*=16777619u; h^=secret; h*=16777619u; return h; }
static uint32_t SimpleCredentialProof(uint32_t passwordHash, uint32_t nonce)
{ uint32_t h=2166136261u; h^=passwordHash; h*=16777619u; h^=nonce; h*=16777619u; return h; }
static uint32_t SimpleAuthenticator(uint32_t pid, uint32_t nonce, uint32_t secret)
{ return (pid * 2654435761u) ^ nonce ^ secret ^ 0x9E3779B9u; }

// SHOW: COMMAND MAC – GENERATION
// CalculateCommandMac: the ONE Command MAC used everywhere -- legitimate
// commands, Gateway verification, and the Privilege Escalation scenario.
// Input: sessionKey + command fields + role/permissionMask. Output: uint32 MAC.
static uint32_t CalculateCommandMac(uint32_t sessionKey, uint32_t pid, uint32_t dev, uint8_t cmd,
                                     uint32_t sentMs, uint32_t seq, uint8_t role, uint32_t perm)
{
  uint32_t h = 2166136261u;
  h ^= sessionKey; h *= 16777619u; h ^= pid; h *= 16777619u; h ^= dev; h *= 16777619u;
  h ^= cmd; h *= 16777619u; h ^= sentMs; h *= 16777619u; h ^= seq; h *= 16777619u;
  h ^= role; h *= 16777619u; h ^= perm; h *= 16777619u;
  return h;
}

// ==================================== SECTION 4: LDAP AND RADIUS ==========
// SHOW: LDAP – LOOKUP
// LdapServerApp: identity directory. Input: LdapQueryHeader. Output: role,
// permissionMask, and credential-proof verdict via LdapReplyHeader.
class LdapServerApp : public Application
{
public:
  void Setup(const std::map<uint32_t, LdapEntry> &dir) { m_dir = dir; }
private:
  void StartApplication() override
  {
    m_sock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_sock->Bind(InetSocketAddress(Ipv4Address::GetAny(), LDAP_PORT));
    m_sock->SetRecvCallback(MakeCallback(&LdapServerApp::ReceiveQuery, this));
  }
  void StopApplication() override { if (m_sock) { m_sock->Close(); m_sock=nullptr; } }

  void ReceiveQuery(Ptr<Socket> sock)
  {
    Address from; Ptr<Packet> p = sock->RecvFrom(from);
    if (!p) return;
    LdapQueryHeader q; if (p->PeekHeader(q) == 0) return;

    auto it = m_dir.find(q.GetPrincipalId());
    bool valid = (it != m_dir.end());
    bool enabled = valid && it->second.enabled;
    uint8_t role = valid ? it->second.role : ROLE_DISABLED;
    uint32_t perm = (valid && enabled) ? it->second.permissionMask : 0;
    uint32_t pwHash = valid ? it->second.passwordHash : 0;
    bool credOk = valid && (q.GetCredProof() == SimpleCredentialProof(pwHash, q.GetCredNonce()));

    LdapReplyHeader r(q.GetReqId(), q.GetPrincipalId(), valid, enabled, credOk, role, perm, pwHash);
    Ptr<Packet> out = Create<Packet>(0); out->AddHeader(r);
    m_sock->SendTo(out, 0, from);
  }
  Ptr<Socket> m_sock; std::map<uint32_t, LdapEntry> m_dir;
};

// RadiusServerApp: AAA (Authentication via LDAP, Authorization, Accounting).
// Optional LDAP cache -- credential proof is always re-checked on a hit.
class RadiusServerApp : public Application
{
public:
  void Setup(Ipv4Address ldapAddr, bool enableCache) { m_ldapAddr = ldapAddr; m_enableCache = enableCache; }
  uint8_t GetRole(uint32_t pid) const { auto it=m_role.find(pid); return it==m_role.end()?ROLE_DISABLED:it->second; }
  uint32_t GetPerm(uint32_t pid) const { auto it=m_perm.find(pid); return it==m_perm.end()?0:it->second; }
  uint32_t GetSessionId(uint32_t pid) const { auto it=m_sessionId.find(pid); return it==m_sessionId.end()?0:it->second; }
private:
  struct Pending { uint32_t principalId=0; Address to; };
  struct CacheEntry { uint8_t role=ROLE_DISABLED; uint32_t perm=0; uint32_t pwHash=0; bool enabled=false; };

  void StartApplication() override
  {
    m_authSock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_authSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), RADIUS_PORT));
    m_authSock->SetRecvCallback(MakeCallback(&RadiusServerApp::ReceiveAuth, this));
    m_ldapSock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_ldapSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), 0));
    m_ldapSock->SetRecvCallback(MakeCallback(&RadiusServerApp::ReceiveLdapReply, this));
    m_acctSock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_acctSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), RADIUS_ACCT_PORT));
    m_acctSock->SetRecvCallback(MakeCallback(&RadiusServerApp::ReceiveAcct, this));
  }
  void StopApplication() override
  { if (m_authSock) { m_authSock->Close(); m_authSock=nullptr; } if (m_ldapSock) { m_ldapSock->Close(); m_ldapSock=nullptr; }
    if (m_acctSock) { m_acctSock->Close(); m_acctSock=nullptr; } }

  // SHOW: RADIUS – AUTHENTICATION
  // ReceiveAuth: EAP arrives inside the RADIUS packet. On a cache hit the
  // credential proof is still re-checked; on a miss it queries LDAP.
  void ReceiveAuth(Ptr<Socket> sock)
  {
    Address from; Ptr<Packet> p = sock->RecvFrom(from);
    if (!p) return;
    RadiusAuthHeader a; p->RemoveHeader(a);
    EapHeader eap; if (p->PeekHeader(eap) == 0 || eap.GetCode() != EAP_RESPONSE) return;
    if (a.GetAuth() != SimpleAuthenticator(a.GetPrincipalId(), a.GetNonce(), RADIUS_SECRET)) return;
    g_res.totalAuthRequests++;

    bool isProbe = (a.GetPrincipalId() == CACHE_PROBE_PID);
    uint32_t probeNum = isProbe ? ++m_cacheProbeCount : 0;

    // SHOW: LDAP CACHE – HIT AND MISS
    if (m_enableCache)
    {
      auto cit = m_cache.find(a.GetPrincipalId());
      if (cit != m_cache.end())
      {
        g_res.cacheHits++;
        if (isProbe)
        {
          std::cout << "[Test Request " << probeNum << "] -> CACHE HIT\n";
          if (probeNum == g_cacheProbeTotal) std::cout << LINE_THICK << "\n";
        }
        // Always re-check the credential proof on a cache hit.
        bool credOk = (a.GetCredProof() == SimpleCredentialProof(cit->second.pwHash, a.GetNonce()));
        FinishAuth(a.GetPrincipalId(), from, cit->second.enabled && credOk, cit->second.role, cit->second.perm);
        return;
      }
      g_res.cacheMisses++;
    }

    uint32_t reqId = ++m_reqCounter;
    m_pending[reqId] = { a.GetPrincipalId(), from };
    LdapQueryHeader q(reqId, a.GetPrincipalId(), a.GetNonce(), a.GetCredProof());
    Ptr<Packet> out = Create<Packet>(0); out->AddHeader(q);
    g_res.ldapQueries++;
    if (isProbe)
    {
      std::cout << "[Test Request " << probeNum << "] -> LDAP QUERY\n";
      if (probeNum == g_cacheProbeTotal) std::cout << LINE_THICK << "\n";
    }
    m_ldapSock->SendTo(out, 0, InetSocketAddress(m_ldapAddr, LDAP_PORT));
  }
  // ReceiveLdapReply: correlated by requestId (never by arrival order).
  void ReceiveLdapReply(Ptr<Socket> sock)
  {
    Address from; Ptr<Packet> p = sock->RecvFrom(from);
    if (!p) return;
    LdapReplyHeader r; if (p->PeekHeader(r) == 0) return;
    auto pit = m_pending.find(r.GetReqId());
    if (pit == m_pending.end() || pit->second.principalId != r.GetPrincipalId()) return;
    Pending pr = pit->second; m_pending.erase(pit);

    if (m_enableCache && r.IsValid())
      m_cache[r.GetPrincipalId()] = { r.GetRole(), r.GetPerm(), r.GetPasswordHash(), r.IsEnabled() };

    FinishAuth(r.GetPrincipalId(), pr.to, r.IsValid() && r.IsEnabled() && r.IsCredOk(), r.GetRole(), r.GetPerm());
  }
  // FinishAuth: shared by the cache-hit path and the real LDAP-reply path.
  void FinishAuth(uint32_t pid, Address to, bool accept, uint8_t role, uint32_t perm)
  {
    uint32_t sid = ++m_sessionCounter;
    bool isProbe = (pid == CACHE_PROBE_PID);
    if (accept) { m_role[pid]=role; m_perm[pid]=perm; m_sessionId[pid]=sid; if (!isProbe) g_res.authAccepted++; }
    else if (!isProbe) g_res.authRejected++;
    if (!isProbe && g_showAuthenticationFlow)
      std::cout << "[4] RADIUS decision: " << (accept ? "ACCESS-ACCEPT" : "ACCESS-REJECT") << "\n";
    RadiusReplyHeader reply(pid, accept, sid);
    Ptr<Packet> out = Create<Packet>(0); out->AddHeader(reply);
    m_authSock->SendTo(out, 0, to);
  }
  // SHOW: RADIUS – ACCOUNTING
  // ReceiveAcct: minimal Accounting Start(1)/Stop(2) counters.
  void ReceiveAcct(Ptr<Socket> sock)
  {
    Address from; Ptr<Packet> p = sock->RecvFrom(from);
    if (!p) return;
    RadiusAcctHeader h; if (p->PeekHeader(h) == 0) return;
    if (h.GetType() == 1) g_res.acctStarts++; else if (h.GetType() == 2) g_res.acctStops++;
  }

  Ptr<Socket> m_authSock, m_ldapSock, m_acctSock; Ipv4Address m_ldapAddr; bool m_enableCache{false};
  uint32_t m_reqCounter=0, m_sessionCounter=0, m_cacheProbeCount=0;
  std::map<uint32_t, Pending> m_pending;
  std::map<uint32_t, uint8_t> m_role; std::map<uint32_t, uint32_t> m_perm; std::map<uint32_t, uint32_t> m_sessionId;
  std::map<uint32_t, CacheEntry> m_cache;
};

// ============================= SECTION 5: IEEE 802.1X AUTHENTICATOR =======
// SHOW: IEEE 802.1X – AUTHENTICATOR
// Network Access Control: EAP travels inside EAPOL between Supplicant and
// Authenticator, and inside the RADIUS packet between Authenticator and
// RADIUS. Applies RADIUS's decision as the Supplicant's 802.1X state.
class Dot1xAuthenticatorApp : public Application
{
public:
  void Setup(Ipv4Address radiusAddr) { m_radiusAddr = radiusAddr; }
  bool IsAuthorized(uint32_t pid) const
  { auto it = m_state.find(pid); return it != m_state.end() && it->second == DOT1X_AUTHORIZED; }
private:
  void StartApplication() override
  {
    m_eapolSock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_eapolSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), EAPOL_PORT));
    m_eapolSock->SetRecvCallback(MakeCallback(&Dot1xAuthenticatorApp::ReceiveEapol, this));
    m_radiusSock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_radiusSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), 0));
    m_radiusSock->SetRecvCallback(MakeCallback(&Dot1xAuthenticatorApp::ReceiveRadiusReply, this));
  }
  void StopApplication() override
  { if (m_eapolSock) { m_eapolSock->Close(); m_eapolSock=nullptr; } if (m_radiusSock) { m_radiusSock->Close(); m_radiusSock=nullptr; } }

  void ReceiveEapol(Ptr<Socket> sock)
  {
    Address from; Ptr<Packet> p = sock->RecvFrom(from);
    if (!p) return;
    EapolHeader eapol; p->RemoveHeader(eapol);
    EapHeader eap; if (p->PeekHeader(eap) == 0) return;
    if (eap.GetCode() != EAP_RESPONSE) return;

    m_from[eap.GetPrincipalId()] = from;
    if (g_showAuthenticationFlow)
      std::cout << "[2] Authenticator received EAPOL\n"
                << "[3] Authenticator encapsulated EAP inside RADIUS\n";
    uint32_t auth = SimpleAuthenticator(eap.GetPrincipalId(), eap.GetNonce(), RADIUS_SECRET);
    RadiusAuthHeader a(eap.GetPrincipalId(), eap.GetNonce(), auth, eap.GetCredProof());
    Ptr<Packet> out = Create<Packet>(0);
    out->AddHeader(eap); // EAP carried inside the RADIUS packet (inner header)
    out->AddHeader(a);   // RadiusAuthHeader (outer)
    m_radiusSock->SendTo(out, 0, InetSocketAddress(m_radiusAddr, RADIUS_PORT));
  }
  void ReceiveRadiusReply(Ptr<Socket> sock)
  {
    Address from; Ptr<Packet> p = sock->RecvFrom(from);
    if (!p) return;
    RadiusReplyHeader r; if (p->PeekHeader(r) == 0) return;

    Dot1xState st = r.IsAccept() ? DOT1X_AUTHORIZED : DOT1X_UNAUTHORIZED;
    m_state[r.GetPrincipalId()] = st;
    if (st == DOT1X_AUTHORIZED) g_res.dot1xAuthorized++; else g_res.dot1xUnauthorized++;
    if (g_showAuthenticationFlow)
      std::cout << "[5] Authenticator state: " << (r.IsAccept() ? "AUTHORIZED" : "UNAUTHORIZED") << "\n";

    EapHeader eap(r.IsAccept() ? EAP_SUCCESS : EAP_FAILURE, 0, r.GetPrincipalId(), 0, 0, r.GetSessionId());
    EapolHeader eapol;
    Ptr<Packet> out = Create<Packet>(0); out->AddHeader(eap); out->AddHeader(eapol);
    auto it = m_from.find(r.GetPrincipalId());
    if (it != m_from.end()) m_eapolSock->SendTo(out, 0, it->second);
  }
  Ptr<Socket> m_eapolSock, m_radiusSock; Ipv4Address m_radiusAddr;
  std::map<uint32_t, Dot1xState> m_state;
  std::map<uint32_t, Address> m_from;
};

// ==================================== SECTION 6: KERBEROS KDC =============
// Issues tickets only to IEEE 802.1X-authorized principals with a valid RADIUS session.
class KdcApp : public Application
{
public:
  void Setup(RadiusServerApp *radius, Dot1xAuthenticatorApp *authenticator, uint32_t lifetimeMs)
  { m_radius = radius; m_authenticator = authenticator; m_lifetimeMs = lifetimeMs; }
private:
  void StartApplication() override
  {
    m_sock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_sock->Bind(InetSocketAddress(Ipv4Address::GetAny(), KDC_PORT));
    m_sock->SetRecvCallback(MakeCallback(&KdcApp::IssueKerberosTicket, this));
  }
  void StopApplication() override { if (m_sock) { m_sock->Close(); m_sock=nullptr; } }

  // SHOW: KERBEROS – TICKET ISSUING
  // IssueKerberosTicket: input TicketRequestHeader. Issues a ticket only if
  // 802.1X AUTHORIZED and the sessionId matches RADIUS's accepted session.
  void IssueKerberosTicket(Ptr<Socket> sock)
  {
    Address from; Ptr<Packet> p = sock->RecvFrom(from);
    if (!p) return;
    TicketRequestHeader tr; if (p->PeekHeader(tr) == 0) return;
    if (!m_authenticator->IsAuthorized(tr.GetPrincipalId())) return;
    if (tr.GetSessionId() != m_radius->GetSessionId(tr.GetPrincipalId())) return; // Verify that the ticket request references the current authenticated RADIUS session.

    uint32_t sessionKey = SimpleAuthenticator(tr.GetPrincipalId(), tr.GetSessionId(), 0xC0FFEEu);
    uint32_t expiry = uint32_t(Simulator::Now().GetMilliSeconds()) + m_lifetimeMs;
    TicketResponseHeader tk(TICKET_MAGIC, tr.GetPrincipalId(), tr.GetSessionId(), sessionKey, expiry,
                             m_radius->GetPerm(tr.GetPrincipalId()), m_radius->GetRole(tr.GetPrincipalId()));
    g_res.ticketsIssued++;
    if (g_showAuthenticationFlow) std::cout << "[6] Kerberos ticket issued\n" << LINE_THIN << "\n";
    Ptr<Packet> out = Create<Packet>(0); out->AddHeader(tk);
    m_sock->SendTo(out, 0, from);
  }
  Ptr<Socket> m_sock; RadiusServerApp *m_radius{nullptr}; Dot1xAuthenticatorApp *m_authenticator{nullptr};
  uint32_t m_lifetimeMs{8000};
};

// ============================== SECTION 7: GATEWAY AND DEVICES ============
// Security Enforcement Point. ProcessGatewayCommand() pipeline:
// ValidateTicket -> ValidateCommandMac -> DetectReplay -> ValidatePermission
// -> StoreAcceptedSequence -> ForwardToDevice.
class SmartHomeGatewayApp : public Application
{
public:
  void Setup(const std::map<uint32_t, Ipv4Address> &deviceAddr, bool enableReplayProtection)
  { m_deviceAddr = deviceAddr; m_enableReplayProtection = enableReplayProtection; }
private:
  void StartApplication() override
  {
    m_rxSock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_rxSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), GATEWAY_PORT));
    m_rxSock->SetRecvCallback(MakeCallback(&SmartHomeGatewayApp::ProcessGatewayCommand, this));
    m_txSock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_txSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), 0));
  }
  void StopApplication() override
  { if (m_rxSock) { m_rxSock->Close(); m_rxSock=nullptr; } if (m_txSock) { m_txSock->Close(); m_txSock=nullptr; } }

  // SHOW: GATEWAY – SECURITY PIPELINE
  // ProcessGatewayCommand: orchestrator only -- each check lives in its own
  // function below, in fixed order.
  void ProcessGatewayCommand(Ptr<Socket> sock)
  {
    Address from; Ptr<Packet> p = sock->RecvFrom(from);
    if (!p) return;
    Ptr<Packet> originalWirePacket = p->Copy();

    TicketResponseHeader ticket;
    if (p->PeekHeader(ticket) == 0) return;
    p->RemoveHeader(ticket);
    CommandRequestHeader cmdReq;
    if (p->PeekHeader(cmdReq) == 0) return;

    uint32_t pid = cmdReq.GetPrincipalId();
    uint8_t cmd = cmdReq.GetCommand();

    if (!ValidateTicket(ticket, cmdReq)) return;
    if (!ValidateCommandMac(ticket, cmdReq)) return;

    bool alreadyAccepted = false;
    if (!DetectReplay(ticket, cmdReq, alreadyAccepted)) return;
    if (!ValidatePermission(cmdReq)) return;

    StoreAcceptedSequence(ticket, cmdReq);
    g_res.commandsAccepted++;
    bool isTelemetry = (cmd == CMD_SEND_TEMPERATURE || cmd == CMD_SEND_MOTION);
    std::cout << (isTelemetry ? "[TELEMETRY ACCEPTED] " : "[COMMAND ACCEPTED] ")
              << PrincipalName(pid) << " -> " << CommandName(cmd) << "\n";

    CaptureLegitimateReplayPacket(pid, cmd, alreadyAccepted, originalWirePacket);
    ForwardToDevice(pid, cmd);
  }

  // SHOW: KERBEROS – TICKET VALIDATION
  // ValidateTicket: magic, expiry, and principal binding.
  bool ValidateTicket(const TicketResponseHeader &ticket, const CommandRequestHeader &cmdReq)
  {
    if (ticket.GetMagic() != TICKET_MAGIC) { g_res.commandsRejected++; return false; }
    uint32_t nowMs = uint32_t(Simulator::Now().GetMilliSeconds());
    if (nowMs > ticket.GetExpiryMs()) { g_res.commandsRejected++; return false; }
    if (ticket.GetPrincipalId() != cmdReq.GetPrincipalId()) { g_res.commandsRejected++; return false; }
    return true;
  }

  // SHOW: COMMAND MAC – VERIFICATION
  // ValidateCommandMac: role/permissionMask are claims in CommandRequestHeader
  // (never the ticket). The Command MAC is always recomputed over the
  // received claims -- MAC verification is never replaced by the ticket
  // comparison alone. A claims mismatch with an invalid MAC is classified as
  // a Privilege Escalation attempt; an invalid MAC with no claims mismatch is
  // a generic Bad Command MAC.
  bool ValidateCommandMac(const TicketResponseHeader &ticket, const CommandRequestHeader &cmdReq)
  {
    bool claimsMismatch = (cmdReq.GetRole() != ticket.GetRoleId()) || (cmdReq.GetPerm() != ticket.GetPermissionMask());

    uint32_t expected = CalculateCommandMac(ticket.GetSessionKey(), cmdReq.GetPrincipalId(), cmdReq.GetDeviceId(),
                                             cmdReq.GetCommand(), cmdReq.GetSentMs(), cmdReq.GetSeq(),
                                             cmdReq.GetRole(), cmdReq.GetPerm());
    bool macValid = (cmdReq.GetMac() == expected);

    if (claimsMismatch && !macValid) return HandlePrivilegeEscalation(cmdReq);

    if (!macValid)
    {
      g_res.dropBadCommandMac++; g_res.commandsRejected++;
      return false;
    }
    return true;
  }

  // SHOW: PRIVILEGE ESCALATION – DETECTION AND BLOCKING
  // Detected always; accepted/dropped depends purely on the protection flag.
  bool HandlePrivilegeEscalation(const CommandRequestHeader &cmdReq)
  {
    g_res.privilegeEscalationDetected++;
    std::cout << "Command MAC mismatch detected\n";
    if (g_enablePrivilegeEscalationProtection)
    {
      g_res.dropPrivilegeEscalation++; g_res.commandsRejected++;
      std::cout << "Attack blocked\n" << LINE_THICK << "\n";
      return false;
    }
    g_res.privilegeEscalationAccepted++;
    std::cout << "Attack accepted\n" << LINE_THICK << "\n";
    return true;
  }

  // SHOW: ANTI-REPLAY – DUPLICATE DETECTION
  // DetectReplay: per (principalId, sessionId) Sequence Number set.
  // Always detects a duplicate; only rejects it when protection is on.
  bool DetectReplay(const TicketResponseHeader &ticket, const CommandRequestHeader &cmdReq, bool &alreadyAccepted)
  {
    std::pair<uint32_t,uint32_t> sk(cmdReq.GetPrincipalId(), ticket.GetSessionId());
    alreadyAccepted = m_acceptedSequences[sk].count(cmdReq.GetSeq()) > 0;
    if (!alreadyAccepted) return true;
    g_res.replayDetected++;
    std::cout << "Duplicate sequence detected\n";
    if (m_enableReplayProtection)
    {
      g_res.dropReplay++; g_res.commandsRejected++;
      std::cout << "Replay blocked\n" << LINE_THICK << "\n";
      return false;
    }
    g_res.replayAccepted++;
    std::cout << "Replay packet accepted\n" << LINE_THICK << "\n";
    return true;
  }

  // SHOW: RBAC – PERMISSION CHECK
  // ValidatePermission: required permission vs. permissionMask in the command.
  bool ValidatePermission(const CommandRequestHeader &cmdReq)
  {
    uint32_t required = RequiredPermission(cmdReq.GetCommand());
    if ((cmdReq.GetPerm() & required) != 0) return true;
    g_res.dropUnauthorizedPermission++; g_res.commandsRejected++;
    std::cout << "[RBAC DENIED] " << PrincipalName(cmdReq.GetPrincipalId()) << " -> " << CommandName(cmdReq.GetCommand()) << "\n"
              << "Reason: " << RoleName(cmdReq.GetRole()) << " role does not include "
              << PermissionName(required) << " permission\n";
    return false;
  }

  // StoreAcceptedSequence: record the Sequence Number only after every prior
  // check passed, so a rejected command never consumes one.
  void StoreAcceptedSequence(const TicketResponseHeader &ticket, const CommandRequestHeader &cmdReq)
  {
    std::pair<uint32_t,uint32_t> sk(cmdReq.GetPrincipalId(), ticket.GetSessionId());
    m_acceptedSequences[sk].insert(cmdReq.GetSeq());
  }

  // SHOW: REPLAY ATTACK – PACKET CAPTURE
  // CaptureLegitimateReplayPacket: keep exactly one accepted, first-time,
  // Ahmad OPEN_DOOR packet for ReplayAttackApp to resend later.
  void CaptureLegitimateReplayPacket(uint32_t pid, uint8_t cmd, bool alreadyAccepted, Ptr<Packet> wirePacket)
  {
    if (!alreadyAccepted && pid == USER_AHMAD && cmd == CMD_OPEN_DOOR && !g_capturedOpenDoorPacket)
      g_capturedOpenDoorPacket = wirePacket;
  }

  // ForwardToDevice: send the approved command to the target actuator.
  void ForwardToDevice(uint32_t pid, uint8_t cmd)
  {
    uint32_t dev = TargetDeviceForCommand(cmd);
    if (dev == 0) return;
    auto it = m_deviceAddr.find(dev);
    if (it == m_deviceAddr.end()) return;
    ExecuteHeader exec(pid, dev, cmd);
    Ptr<Packet> out = Create<Packet>(0); out->AddHeader(exec);
    m_txSock->SendTo(out, 0, InetSocketAddress(it->second, DEVICE_PORT));
  }

  Ptr<Socket> m_rxSock, m_txSock;
  std::map<uint32_t, Ipv4Address> m_deviceAddr;
  bool m_enableReplayProtection{true};
  std::map<std::pair<uint32_t,uint32_t>, std::set<uint32_t>> m_acceptedSequences;
};

class SmartDeviceApp : public Application
{
public:
  void Setup(const std::string &name) { m_name = name; }
private:
  void StartApplication() override
  {
    m_sock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_sock->Bind(InetSocketAddress(Ipv4Address::GetAny(), DEVICE_PORT));
    m_sock->SetRecvCallback(MakeCallback(&SmartDeviceApp::Receive, this));
  }
  void StopApplication() override { if (m_sock) { m_sock->Close(); m_sock=nullptr; } }
  void Receive(Ptr<Socket> sock)
  {
    Address from; Ptr<Packet> p = sock->RecvFrom(from);
    if (!p) return;
    ExecuteHeader e; if (p->PeekHeader(e) == 0) return;
    std::cout << "[DEVICE EXECUTED] " << m_name << " -> " << CommandName(e.GetCommand()) << "\n";
  }
  Ptr<Socket> m_sock; std::string m_name;
};

// ============================= SECTION 8: PRINCIPAL WORKFLOW ==============
// Drives the full client path (EAPOL -> Ticket -> Command) for both users
// and sensors. One command per scheduled task -- no retries, single-shot.
struct CommandTask { double offsetS; uint8_t command; };

class SmartHomeUserApp : public Application
{
public:
  void Setup(const UserProfile &profile, uint32_t ownDeviceId, Ipv4Address authenticatorAddr, Ipv4Address radiusAddr,
             Ipv4Address gwAddr, Ipv4Address kdcAddr, const std::vector<CommandTask> &tasks, Time start, Time stop)
  {
    m_principalId = profile.principalId; m_ownDeviceId = ownDeviceId;
    m_authenticatorAddr = authenticatorAddr; m_radiusAddr = radiusAddr; m_gwAddr = gwAddr; m_kdcAddr = kdcAddr;
    m_passwordHash = SimplePasswordHash(profile.passwordSecret, profile.salt);
    m_tasks = tasks; m_start = start; m_stop = stop;
  }
private:
  void StartApplication() override
  {
    m_authSock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_authSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), 0));
    m_authSock->SetRecvCallback(MakeCallback(&SmartHomeUserApp::ReceiveEapolResult, this));
    m_kdcSock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_kdcSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), 0));
    m_kdcSock->SetRecvCallback(MakeCallback(&SmartHomeUserApp::ReceiveTicket, this));
    m_cmdSock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_cmdSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), 0));
    m_acctSock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_acctSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), 0));
    Simulator::Schedule(m_start, &SmartHomeUserApp::SendEapolRequest, this);
    if (m_stop > MilliSeconds(50))
      Simulator::Schedule(m_stop - MilliSeconds(50), &SmartHomeUserApp::SendAccounting, this, 2);
  }
  void StopApplication() override
  {
    if (m_authSock) { m_authSock->Close(); m_authSock=nullptr; }
    if (m_kdcSock) { m_kdcSock->Close(); m_kdcSock=nullptr; }
    if (m_cmdSock) { m_cmdSock->Close(); m_cmdSock=nullptr; }
    if (m_acctSock) { m_acctSock->Close(); m_acctSock=nullptr; }
  }

  // SendAccounting: minimal RADIUS Accounting Start(1)/Stop(2), each sent at
  // most once, and only for a principal that actually received a ticket.
  void SendAccounting(uint8_t type)
  {
    if (type == 1)
    {
      if (m_accountingStarted || !m_hasTicket) return;
      m_accountingStarted = true;
    }
    else if (type == 2)
    {
      if (!m_accountingStarted) return; // no Start was ever sent (e.g. Lina)
      m_accountingStarted = false;
    }
    RadiusAcctHeader h(m_principalId, type);
    Ptr<Packet> p = Create<Packet>(0); p->AddHeader(h);
    m_acctSock->SendTo(p, 0, InetSocketAddress(m_radiusAddr, RADIUS_ACCT_PORT));
  }

  // SHOW: EAPOL – REQUEST
  // SendEapolRequest: EAP (identity + credential proof) wrapped in EAPOL.
  void SendEapolRequest()
  {
    if (g_showAuthenticationFlow)
      std::cout << LINE_THIN << "\n"
                << "AUTHENTICATION FLOW: " << PrincipalName(m_principalId) << "\n"
                << LINE_THIN << "\n"
                << "[1] Supplicant sent EAP inside EAPOL\n";
    m_nonce = uint32_t(Simulator::Now().GetNanoSeconds() & 0xffffffffu) ^ m_principalId;
    uint32_t proof = SimpleCredentialProof(m_passwordHash, m_nonce);
    EapHeader eap(EAP_RESPONSE, 0, m_principalId, m_nonce, proof, 0);
    EapolHeader eapol;
    Ptr<Packet> p = Create<Packet>(0); p->AddHeader(eap); p->AddHeader(eapol);
    m_authSock->SendTo(p, 0, InetSocketAddress(m_authenticatorAddr, EAPOL_PORT));
  }
  void ReceiveEapolResult(Ptr<Socket> sock)
  {
    Address from; Ptr<Packet> p = sock->RecvFrom(from);
    if (!p) return;
    EapolHeader eapol; p->RemoveHeader(eapol);
    EapHeader eap; if (p->PeekHeader(eap) == 0) return;
    if (eap.GetCode() != EAP_SUCCESS)
    {
      m_dot1xState = DOT1X_UNAUTHORIZED;
      if (g_showAuthenticationFlow) std::cout << "[6] Authentication terminated\n" << LINE_THIN << "\n";
      return;
    }
    m_dot1xState = DOT1X_AUTHORIZED; m_sessionId = eap.GetSessionId();
    SendTicketRequest();
  }
  void SendTicketRequest()
  {
    TicketRequestHeader tr(m_principalId, m_sessionId);
    Ptr<Packet> t = Create<Packet>(0); t->AddHeader(tr);
    m_kdcSock->SendTo(t, 0, InetSocketAddress(m_kdcAddr, KDC_PORT));
  }
  void ReceiveTicket(Ptr<Socket> sock)
  {
    Address from; Ptr<Packet> p = sock->RecvFrom(from);
    if (!p) return;
    TicketResponseHeader tk; if (p->PeekHeader(tk) == 0) return;
    if (tk.GetPrincipalId() != m_principalId || m_hasTicket) return;
    m_ticket = tk; m_hasTicket = true;
    SendAccounting(1);
    for (const auto &task : m_tasks)
      Simulator::Schedule(Seconds(task.offsetS), &SmartHomeUserApp::SendCommand, this, task.command);
  }

  void SendCommand(uint8_t cmd)
  {
    if (m_dot1xState != DOT1X_AUTHORIZED || !m_hasTicket) return;
    uint32_t deviceId = (m_ownDeviceId != 0) ? m_ownDeviceId : TargetDeviceForCommand(cmd);
    uint32_t sentMs = uint32_t(Simulator::Now().GetMilliSeconds());
    CommandRequestHeader creq = CreateCommandPacket(cmd, deviceId, sentMs);
    Ptr<Packet> pkt = Create<Packet>(0); pkt->AddHeader(creq); pkt->AddHeader(m_ticket);
    m_cmdSock->SendTo(pkt, 0, InetSocketAddress(m_gwAddr, GATEWAY_PORT));
  }

  // SHOW: SEQUENCE NUMBER – GENERATION
  // CreateCommandPacket: assigns the next sequence number, then the Command
  // MAC over the TRUE ticket-granted role/permissionMask (may be forged after).
  CommandRequestHeader CreateCommandPacket(uint8_t cmd, uint32_t deviceId, uint32_t sentMs)
  {
    uint32_t seq = m_nextSequence++;
    uint8_t role = m_ticket.GetRoleId();
    uint32_t perm = m_ticket.GetPermissionMask();
    uint32_t mac = CalculateCommandMac(m_ticket.GetSessionKey(), m_principalId, deviceId, cmd, sentMs, seq, role, perm);
    CreatePrivilegeEscalationAttempt(cmd, role, perm);
    return CommandRequestHeader(m_principalId, deviceId, cmd, sentMs, mac, seq, role, perm);
  }

  // SHOW: PRIVILEGE ESCALATION – FORGED CLAIMS
  // Sara (GUEST/LIGHT) forges role=OWNER, permissionMask=DOOR onto the
  // CommandRequestHeader claims only -- the Kerberos ticket is never touched.
  void CreatePrivilegeEscalationAttempt(uint8_t cmd, uint8_t &role, uint32_t &perm)
  {
    if (!g_enablePrivilegeEscalationAttack || m_principalId != USER_SARA || cmd != CMD_OPEN_DOOR) return;
    role = ROLE_OWNER; perm = PERM_DOOR;
    g_res.privilegeEscalationAttempts++;
    std::cout << LINE_THICK << "\n"
              << "PRIVILEGE ESCALATION\n"
              << LINE_THICK << "\n"
              << "Sara forged ROLE and PERMISSION\n";
  }

  Ptr<Socket> m_authSock, m_kdcSock, m_cmdSock, m_acctSock;
  uint32_t m_principalId{0}, m_ownDeviceId{0}, m_passwordHash{0};
  Ipv4Address m_authenticatorAddr, m_radiusAddr, m_gwAddr, m_kdcAddr;
  std::vector<CommandTask> m_tasks; Time m_start, m_stop;
  Dot1xState m_dot1xState{DOT1X_UNAUTHORIZED};
  uint32_t m_nonce{0}, m_sessionId{0}, m_nextSequence{1};
  bool m_hasTicket{false}; TicketResponseHeader m_ticket; bool m_accountingStarted{false};
};

// ================================ SECTION 9: REPLAY ATTACK =================
// Resends the packet captured by SmartHomeGatewayApp::CaptureLegitimateReplayPacket.
// DetectReplay() catches the duplicate; only rejects it when protection is on.
class ReplayAttackApp : public Application
{
public:
  void Setup(Ptr<Packet> *captureSlot, Ipv4Address gwAddr, Time replayTime)
  { m_captureSlot = captureSlot; m_gwAddr = gwAddr; m_replayTime = replayTime; }
private:
  void StartApplication() override
  {
    m_sock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_sock->Bind(InetSocketAddress(Ipv4Address::GetAny(), 0));
    Simulator::Schedule(m_replayTime, &ReplayAttackApp::TrySendReplay, this);
  }
  void StopApplication() override { if (m_sock) { m_sock->Close(); m_sock=nullptr; } }
  // SHOW: REPLAY ATTACK – PACKET RESEND
  void TrySendReplay()
  {
    if (m_sent) return;
    if (!m_captureSlot || !(*m_captureSlot)) { Simulator::Schedule(MilliSeconds(200), &ReplayAttackApp::TrySendReplay, this); return; }
    m_sent = true;
    std::cout << LINE_THICK << "\n"
              << "REPLAY ATTACK\n"
              << LINE_THICK << "\n"
              << "Captured OPEN_DOOR packet replayed\n";
    g_res.replayAttempts++;
    Ptr<Packet> replay = (*m_captureSlot)->Copy();
    m_sock->SendTo(replay, 0, InetSocketAddress(m_gwAddr, GATEWAY_PORT));
  }
  Ptr<Socket> m_sock; Ptr<Packet> *m_captureSlot{nullptr}; Ipv4Address m_gwAddr; Time m_replayTime; bool m_sent{false};
};

// ============================ SECTION 9B: LDAP CACHE DEMO (isolated) ======
// CacheProbeApp -- LDAP Cache Measurement Probe: an isolated performance
// test that sends RADIUS authentication probes directly, to measure cache
// hits and the resulting reduction in LDAP queries. It is NOT part of the
// main IEEE 802.1X path: it never touches EAPOL, never requests a Kerberos
// ticket, never sends a command, and never sends Accounting -- fully
// isolated from the main scenario, Replay Attack, and Privilege Escalation.
// Enabled only with --enableCacheDemo=1.
class CacheProbeApp : public Application
{
public:
  void Setup(uint32_t principalId, uint32_t passwordHash, Ipv4Address radiusAddr, std::vector<Time> probeTimes)
  { m_principalId = principalId; m_passwordHash = passwordHash; m_radiusAddr = radiusAddr; m_probeTimes = probeTimes; }
private:
  void StartApplication() override
  {
    m_sock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_sock->Bind(InetSocketAddress(Ipv4Address::GetAny(), 0));
    for (Time t : m_probeTimes)
      Simulator::Schedule(t, &CacheProbeApp::SendProbe, this);
  }
  void StopApplication() override { if (m_sock) { m_sock->Close(); m_sock=nullptr; } }

  // SendProbe: same wire format the Authenticator forwards to RADIUS
  // (RadiusAuthHeader + inner EapHeader), with a fresh nonce each time.
  // Console output: no per-request "sent" line here -- RadiusServerApp
  // prints one "[Test Request N] -> ..." result line per request instead.
  void SendProbe()
  {
    if (m_probeIndex == 0) std::cout << LINE_THICK << "\nLDAP CACHE TEST\n" << LINE_THICK << "\n";
    ++m_probeIndex;

    uint32_t nonce = uint32_t(Simulator::Now().GetNanoSeconds() & 0xffffffffu) ^ m_principalId ^ 0x50524F42u;
    uint32_t proof = SimpleCredentialProof(m_passwordHash, nonce);
    uint32_t auth = SimpleAuthenticator(m_principalId, nonce, RADIUS_SECRET);
    EapHeader eap(EAP_RESPONSE, 0, m_principalId, nonce, proof, 0);
    RadiusAuthHeader a(m_principalId, nonce, auth, proof);
    Ptr<Packet> p = Create<Packet>(0); p->AddHeader(eap); p->AddHeader(a);
    m_sock->SendTo(p, 0, InetSocketAddress(m_radiusAddr, RADIUS_PORT));
  }
  Ptr<Socket> m_sock; uint32_t m_principalId{0}, m_passwordHash{0};
  Ipv4Address m_radiusAddr; std::vector<Time> m_probeTimes; size_t m_probeIndex{0};
};

// =========================== SECTION 10: MAIN, TOPOLOGY, AND RESULTS ======

// Node layout, shared by every Install* helper below.
enum NodeIndex
{
  N_AUTH=0, N_RADIUS=1, N_LDAP=2, N_KDC=3, N_GW=4, N_DOOR=5, N_LIGHT=6, N_PLUG=7,
  N_TEMP=8, N_MOTION=9, N_AHMAD=10, N_SARA=11, N_OMAR=12, N_LINA=13, N_REPLAY=14,
  N_CACHE_PROBE=15, N_CAMERA=16, N_COUNT=17
};

struct Topology
{
  NodeContainer nodes;
  Ipv4InterfaceContainer ifs;
  Ipv4Address Addr(int idx) const { return ifs.GetAddress(idx); }
};

// Attack/protection flags parsed from the command line.
struct RunConfig
{
  double simTime = 15.0;
  bool enableLdapCache = false;
  bool enableCacheDemo = false;
  bool enableReplayAttack = false, enableReplayProtection = true;
  bool enablePrivilegeEscalationAttack = false, enablePrivilegeEscalationProtection = true;
  bool showAuthenticationFlow = true;
};

static void RegisterPrincipalNames()
{
  g_names[USER_AHMAD]="Ahmad"; g_names[USER_SARA]="Sara"; g_names[USER_OMAR]="Omar"; g_names[USER_LINA]="Lina";
  g_names[DEV_TEMPERATURE]="TemperatureSensor"; g_names[DEV_MOTION]="MotionSensor";
  g_names[CACHE_PROBE_PID]="CacheProbe";
}

// BuildLdapDirectory: identities, roles, permissions, and password hashes.
static std::map<uint32_t, LdapEntry> BuildLdapDirectory()
{
  std::map<uint32_t, LdapEntry> dir;
  auto add = [&](uint32_t pid, uint8_t role, bool enabled, uint32_t perm, uint32_t secret, uint32_t salt)
  { LdapEntry e; e.role=role; e.enabled=enabled; e.permissionMask=perm;
    e.passwordHash=SimplePasswordHash(secret, salt); dir[pid]=e; };
  add(USER_AHMAD, ROLE_OWNER,       true,  PERM_TELEMETRY|PERM_DOOR|PERM_LIGHT|PERM_CAMERA|PERM_PLUG, 0xA1B2C3D4, 0x0000A100);
  add(USER_SARA,  ROLE_GUEST,       true,  PERM_LIGHT,                                                0xB2C3D4E5, 0x0000A102);
  add(USER_OMAR,  ROLE_MAINTENANCE, true,  PERM_TELEMETRY|PERM_PLUG,                                  0xC3D4E5F6, 0x0000A103);
  add(USER_LINA,  ROLE_DISABLED,    false, 0,                                                         0xD4E5F607, 0x0000A104);
  add(DEV_TEMPERATURE, ROLE_DEVICE, true, PERM_TELEMETRY, 0xE5F60718, 0x0000A105);
  add(DEV_MOTION,      ROLE_DEVICE, true, PERM_TELEMETRY, 0xF6071829, 0x0000A106);
  add(CACHE_PROBE_PID, ROLE_GUEST,  true, PERM_TELEMETRY, 0x11223344, 0x0000A200); // --enableCacheDemo only
  return dir;
}

// CreateNetworkTopology: one CSMA segment, IPv4 stack, N_COUNT nodes.
static Topology CreateNetworkTopology()
{
  Topology topo;
  topo.nodes.Create(N_COUNT);
  CsmaHelper csma;
  csma.SetChannelAttribute("DataRate", StringValue("10Mbps"));
  csma.SetChannelAttribute("Delay", StringValue("2ms"));
  NetDeviceContainer devs = csma.Install(topo.nodes);
  InternetStackHelper internet;
  internet.Install(topo.nodes);
  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.1.1.0", "255.255.255.0");
  topo.ifs = ipv4.Assign(devs);
  return topo;
}

// InstallServers: LDAP, RADIUS, 802.1X Authenticator, Kerberos KDC.
static void InstallServers(Topology &topo, const std::map<uint32_t, LdapEntry> &dir, const RunConfig &cfg)
{
  Ptr<LdapServerApp> ldap = CreateObject<LdapServerApp>();
  ldap->Setup(dir);
  topo.nodes.Get(N_LDAP)->AddApplication(ldap);

  Ptr<RadiusServerApp> radius = CreateObject<RadiusServerApp>();
  radius->Setup(topo.Addr(N_LDAP), cfg.enableLdapCache);
  topo.nodes.Get(N_RADIUS)->AddApplication(radius);

  Ptr<Dot1xAuthenticatorApp> auth = CreateObject<Dot1xAuthenticatorApp>();
  auth->Setup(topo.Addr(N_RADIUS));
  topo.nodes.Get(N_AUTH)->AddApplication(auth);

  Ptr<KdcApp> kdc = CreateObject<KdcApp>();
  kdc->Setup(GetPointer(radius), GetPointer(auth), 25000);
  topo.nodes.Get(N_KDC)->AddApplication(kdc);

  ldap->SetStartTime(Seconds(0.0));
  ldap->SetStopTime(Seconds(cfg.simTime));

  radius->SetStartTime(Seconds(0.0));
  radius->SetStopTime(Seconds(cfg.simTime));

  auth->SetStartTime(Seconds(0.0));
  auth->SetStopTime(Seconds(cfg.simTime));

  kdc->SetStartTime(Seconds(0.0));
  kdc->SetStopTime(Seconds(cfg.simTime));
}

// InstallGateway: Security Enforcement Point (SECTION 7).
static void InstallGateway(Topology &topo, const RunConfig &cfg)
{
  std::map<uint32_t, Ipv4Address> deviceAddr;
  deviceAddr[DEV_DOOR]=topo.Addr(N_DOOR); deviceAddr[DEV_LIGHT]=topo.Addr(N_LIGHT);
  deviceAddr[DEV_CAMERA]=topo.Addr(N_CAMERA); deviceAddr[DEV_PLUG]=topo.Addr(N_PLUG);
  Ptr<SmartHomeGatewayApp> gw = CreateObject<SmartHomeGatewayApp>();
  gw->Setup(deviceAddr, cfg.enableReplayProtection);
  topo.nodes.Get(N_GW)->AddApplication(gw);
  gw->SetStartTime(Seconds(0.0)); gw->SetStopTime(Seconds(cfg.simTime));
}

// InstallDevices: passive actuators (Door, Light, Camera, Plug).
static void InstallDevices(Topology &topo, const RunConfig &cfg)
{
  auto add = [&](int idx, const std::string &name)
  { Ptr<SmartDeviceApp> d = CreateObject<SmartDeviceApp>(); d->Setup(name);
    topo.nodes.Get(idx)->AddApplication(d);
    d->SetStartTime(Seconds(0.0)); d->SetStopTime(Seconds(cfg.simTime)); };
  add(N_DOOR, "Door"); add(N_LIGHT, "Light"); add(N_CAMERA, "Camera"); add(N_PLUG, "Plug");
}

// InstallUsers: the one normal scenario -- Ahmad, Sara, Omar, Lina, two sensors.
static void InstallUsers(Topology &topo, const RunConfig &cfg)
{
  auto add = [&](int idx, const UserProfile &prof, uint32_t ownDev, std::vector<CommandTask> tasks, double startS)
  { Ptr<SmartHomeUserApp> u = CreateObject<SmartHomeUserApp>();
    u->Setup(prof, ownDev, topo.Addr(N_AUTH), topo.Addr(N_RADIUS), topo.Addr(N_GW), topo.Addr(N_KDC),
             tasks, Seconds(startS), Seconds(cfg.simTime));
    topo.nodes.Get(idx)->AddApplication(u);
    u->SetStartTime(Seconds(0.0)); u->SetStopTime(Seconds(cfg.simTime)); };

  add(N_AHMAD,  {USER_AHMAD, 0xA1B2C3D4, 0x0000A100}, 0, { {1.0, CMD_OPEN_DOOR}, {1.2, CMD_CAMERA_VIEW} }, 0.0);
  add(N_SARA,   {USER_SARA,  0xB2C3D4E5, 0x0000A102}, 0, { {1.5, CMD_LIGHT_ON}, {2.0, CMD_OPEN_DOOR} },     0.2);
  add(N_OMAR,   {USER_OMAR,  0xC3D4E5F6, 0x0000A103}, 0, { {1.5, CMD_PLUG_ON} },                            0.4);
  add(N_LINA,   {USER_LINA,  0xD4E5F607, 0x0000A104}, 0, { },                                               0.6);
  add(N_TEMP,   {DEV_TEMPERATURE, 0xE5F60718, 0x0000A105}, DEV_TEMPERATURE,
      { {1.0, CMD_SEND_TEMPERATURE} }, 0.8);
  add(N_MOTION, {DEV_MOTION, 0xF6071829, 0x0000A106}, DEV_MOTION,
      { {1.0, CMD_SEND_MOTION} }, 1.0);
}

// InstallReplayAttacker: captures and replays Ahmad's OPEN_DOOR once.
static void InstallReplayAttacker(Topology &topo, const RunConfig &cfg)
{
  Ptr<ReplayAttackApp> ra = CreateObject<ReplayAttackApp>();
  ra->Setup(&g_capturedOpenDoorPacket, topo.Addr(N_GW), Seconds(4.0));
  topo.nodes.Get(N_REPLAY)->AddApplication(ra);
  ra->SetStartTime(Seconds(0.0)); ra->SetStopTime(Seconds(cfg.simTime));
}

// InstallCacheProbe: isolated LDAP Cache demo (--enableCacheDemo=1) -- three
// direct RADIUS probes for a dedicated principal, independent of the main
// scenario: first probe = Cache Miss, next two = Cache Hits.
static void InstallCacheProbe(Topology &topo, const RunConfig &cfg)
{
  Ptr<CacheProbeApp> probe = CreateObject<CacheProbeApp>();
  uint32_t pwHash = SimplePasswordHash(0x11223344, 0x0000A200);
  // Scheduled after all normal smart-home commands/RBAC checks (~2.2s) and
  // after the default Replay Attack time (4.0s), so the LDAP Cache Test
  // section is never interrupted by other scenario output.
  std::vector<Time> probeTimes = { Seconds(6.0), Seconds(6.5), Seconds(7.0) };
  g_cacheProbeTotal = uint32_t(probeTimes.size());
  probe->Setup(CACHE_PROBE_PID, pwHash, topo.Addr(N_RADIUS), probeTimes);
  topo.nodes.Get(N_CACHE_PROBE)->AddApplication(probe);
  probe->SetStartTime(Seconds(0.0)); probe->SetStopTime(Seconds(cfg.simTime));
}

// SHOW: FINAL RESULTS
static void PrintResults()
{
  std::cout
    << "\n" << LINE_THICK << "\n"
    << "FINAL SIMULATION RESULTS\n"
    << LINE_THICK << "\n"

    << "\n[1] Authentication and IEEE 802.1X\n"
    << "Accepted                 : " << g_res.authAccepted << "\n"
    << "Rejected                 : " << g_res.authRejected << "\n"
    << "Authorized               : " << g_res.dot1xAuthorized << "\n"
    << "Unauthorized             : " << g_res.dot1xUnauthorized << "\n"

    << "\n[2] LDAP and Cache\n"
    << "Total Authentication Requests : " << g_res.totalAuthRequests << "\n"
    << "LDAP Queries                  : " << g_res.ldapQueries << "\n"
    << "Cache Hits                    : " << g_res.cacheHits << "\n"
    << "Cache Misses                  : " << g_res.cacheMisses << "\n"
    << "LDAP Queries Saved            : " << g_res.cacheHits << "\n"

    << "\n[3] RADIUS Accounting\n"
    << "Accounting Starts        : " << g_res.acctStarts << "\n"
    << "Accounting Stops         : " << g_res.acctStops << "\n"

    << "\n[4] Kerberos\n"
    << "Tickets Issued           : " << g_res.ticketsIssued << "\n"

    << "\n[5] Gateway Security\n"
    << "Commands Accepted        : " << g_res.commandsAccepted << "\n"
    << "Commands Rejected        : " << g_res.commandsRejected << "\n"
    << "Bad Command MAC          : " << g_res.dropBadCommandMac << "\n"
    << "RBAC Denied              : " << g_res.dropUnauthorizedPermission << "\n"

    << "\n[6] Replay Attack\n"
    << "Attempts                 : " << g_res.replayAttempts << "\n"
    << "Detected                 : " << g_res.replayDetected << "\n"
    << "Accepted                 : " << g_res.replayAccepted << "\n"
    << "Blocked                  : " << g_res.dropReplay << "\n"

    << "\n[7] Privilege Escalation\n"
    << "Attempts                 : " << g_res.privilegeEscalationAttempts << "\n"
    << "Detected                 : " << g_res.privilegeEscalationDetected << "\n"
    << "Accepted                 : " << g_res.privilegeEscalationAccepted << "\n"
    << "Blocked                  : " << g_res.dropPrivilegeEscalation << "\n"

    << "\n" << LINE_THICK << "\n";
}

static RunConfig ParseArgs(int argc, char *argv[])
{
  RunConfig cfg;
  CommandLine cmd;
  cmd.AddValue("simTime", "Simulation time (s)", cfg.simTime);
  cmd.AddValue("enableLdapCache", "Cache RADIUS-side role/permissionMask/passwordHash per principal", cfg.enableLdapCache);
  cmd.AddValue("enableCacheDemo", "Run an isolated LDAP Cache test (3 direct RADIUS auth requests)", cfg.enableCacheDemo);
  cmd.AddValue("showAuthenticationFlow", "Print the 6-step AUTHENTICATION FLOW block per principal (console only)",
               cfg.showAuthenticationFlow);
  cmd.AddValue("enableReplayAttack", "Enable one controlled OPEN_DOOR replay attack", cfg.enableReplayAttack);
  cmd.AddValue("enableReplayProtection", "Enable Gateway anti-replay sequence check", cfg.enableReplayProtection);
  cmd.AddValue("enablePrivilegeEscalationAttack", "Sara forges OWNER role + DOOR permission",
               cfg.enablePrivilegeEscalationAttack);
  cmd.AddValue("enablePrivilegeEscalationProtection", "Gateway Command MAC also protects role+permissionMask",
               cfg.enablePrivilegeEscalationProtection);
  cmd.Parse(argc, argv);
  return cfg;
}

// main: reads like pseudocode -- every step is a named helper above.
int main(int argc, char *argv[])
{
  RunConfig cfg = ParseArgs(argc, argv);
  g_enablePrivilegeEscalationAttack = cfg.enablePrivilegeEscalationAttack;
  g_enablePrivilegeEscalationProtection = cfg.enablePrivilegeEscalationProtection;
  g_showAuthenticationFlow = cfg.showAuthenticationFlow;

  RegisterPrincipalNames();
  std::map<uint32_t, LdapEntry> dir = BuildLdapDirectory();

  Topology topo = CreateNetworkTopology();
  InstallServers(topo, dir, cfg);
  InstallGateway(topo, cfg);
  InstallDevices(topo, cfg);
  InstallUsers(topo, cfg);
  if (cfg.enableReplayAttack) InstallReplayAttacker(topo, cfg);
  if (cfg.enableCacheDemo) InstallCacheProbe(topo, cfg);

  Simulator::Stop(Seconds(cfg.simTime));
  Simulator::Run();

  PrintResults();

  Simulator::Destroy();
  return 0;
}
