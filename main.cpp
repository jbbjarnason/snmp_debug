#include <string_view>
#include <string>
#include <exception>
#include <thread>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

static constexpr std::string_view username{ "jonbjarni" };
static constexpr std::string_view authKey{ "jonbjarni" };
static constexpr std::string_view privKey{ "jonbjarni" };
static const oid         objid_mib[] = { 1, 3, 6, 1, 2, 1 };


static void walk(snmp_session& session,const std::string& peername) {

    session.version = 3;
    session.peername = (char*)peername.c_str();
    session.securityName = (char*)username.data();
    session.securityNameLen = username.size();
    session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
    session.securityAuthProto = usmHMACSHA1AuthProtocol;
    session.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
    session.securityAuthKeyLen = USM_AUTH_KU_LEN;

    const auto authResult{
            generate_Ku(session.securityAuthProto, session.securityAuthProtoLen,
                        (u_char *)authKey.data(), authKey.size(),
                        session.securityAuthKey, &(session.securityAuthKeyLen))};

    if (authResult != SNMPERR_SUCCESS) {
        printf("Something wrong with generating hashed authentication key\n");
        std::abort();
    }

    session.securityPrivProto = usmAESPrivProtocol;
    session.securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;

    session.securityPrivKeyLen = USM_PRIV_KU_LEN;

    const auto privResult{
            generate_Ku(session.securityAuthProto, session.securityAuthProtoLen,
                        (u_char *)privKey.data(), privKey.size(),
                        session.securityPrivKey, &(session.securityPrivKeyLen))};

    if (privResult != SNMPERR_SUCCESS) {
        printf("Something wrong with generating hashed private key\n");
        std::abort();
    }

    void* open_session{ snmp_sess_open(&session) };

    if (open_session == nullptr) {
        printf("Error opening session\n");
        std::abort();
    }

    oid name[MAX_OID_LEN];
    memmove(name, objid_mib, sizeof(objid_mib));
    size_t name_len = sizeof(objid_mib) / sizeof(oid);

    // create an end oid so we know when to stop
    oid end_oid[MAX_OID_LEN];
    size_t end_len = name_len;
    memmove(end_oid, name, end_len * sizeof(oid));
    end_oid[end_len - 1]++;

    while (true) {

        netsnmp_pdu *pdu{snmp_pdu_create(SNMP_MSG_GETBULK)};
        if (!pdu) {
            printf("Unable to create pdu\n");
            std::abort();
        }
        pdu->non_repeaters = 0;
        pdu->max_repetitions = 10;

        if (!snmp_add_null_var(pdu, name, name_len)) {
            snmp_free_pdu(pdu);
            printf("Error adding null var\n");
            std::abort();
        }

        netsnmp_pdu *pdu_response{nullptr};

        const auto status{snmp_sess_synch_response(open_session, pdu, &pdu_response)};

        if (status == STAT_TIMEOUT) {
            printf("Timeout !!!\n");
            std::abort();
        }
        if (status == STAT_ERROR) {
            char *err{nullptr};
            snmp_sess_error(open_session, nullptr, nullptr, &err);
            printf("Unable to sync, error code: %s\n", err);
            SNMP_FREE(err);
            std::abort();
        }
        if (status == STAT_SUCCESS) {
            if (pdu_response->errstat != SNMP_ERR_NOERROR) {
                printf("error from pdu response: %s", snmp_errstring(pdu_response->errstat));
                std::abort();
            }

            for (auto *vars{pdu_response->variables}; vars; vars = vars->next_variable) {
                if (snmp_oid_compare(end_oid, end_len, vars->name, vars->name_length) <= 0) {
                    // not a part of this tree, we are done
                    goto close;
                }
                if ((vars->type == SNMP_ENDOFMIBVIEW) || (vars->type == SNMP_NOSUCHOBJECT)
                    || (vars->type == SNMP_NOSUCHINSTANCE)) {
                    // this is an exception so stop, is this an error?
                    goto close;
                }
                if (snmp_oid_compare(name, name_len, vars->name, vars->name_length) >= 0) {
                    // error - OID is increasing
                    goto close;
                }

                //print_variable(vars->name, vars->name_length, vars);
                // Todo: do something with var

                if (vars->next_variable == nullptr) {
                    // it's the last variable let's copy a new start to name
                    memmove((char *) name, (char *) vars->name, vars->name_length * sizeof(oid));
                    name_len = vars->name_length;
                }
            }

        }
    }

close:

    size_t id{ std::hash<std::thread::id>{}(std::this_thread::get_id()) };
    printf("closing  %zu\n", id);

    snmp_sess_close(open_session);

    if (session.securityEngineID)
        free(session.securityEngineID);
    if (session.contextEngineID)
        free(session.contextEngineID);
}

struct snmpLog {

    static int logCb(int /*majorID*/, int /*minorID*/, void* serverarg, void* /* clientarg */)
    {
        const auto msg{ static_cast<struct snmp_log_message*>(serverarg) };
        printf("[%zu] %s \n", std::hash<std::thread::id>{}(std::this_thread::get_id()),  msg->msg);
        return 42; // return value is not used within snmp call_callbacks function
    }

    snmpLog()
    {
        snmp_register_callback(SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_LOGGING, &logCb, nullptr);
        snmp_enable_calllog(); // propagate all logs to the above callback
        //snmp_enable_stderrlog();
        snmp_disable_stderrlog(); // disable any log from appearing in std out
        snmp_set_do_debugging(1); // enable all logging levels
    }
};

static snmpLog globalLogging;



int main() {
    init_snmp("snmpapp");
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, TRUE);

    struct snmp_session session_th1{};
    snmp_sess_init(&session_th1);

    struct snmp_session session_th2{};
    snmp_sess_init(&session_th2);

    std::thread th1(walk, std::ref(session_th1), "172.18.0.2:161");
    std::thread th2(walk, std::ref(session_th2), "172.18.0.3:161");

    th1.join();
    th2.join();

//    walk("172.18.0.2:161");

    return 0;
}
