""" Please make sure you read the README file COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file. 
"""
from process import GetProcFromTask
from utils import Cast, GetEnumName
from core.kernelcore import IterateLinkageChain
from core.cvalue import addressof
from core.standard import VT, ArgumentError
from core.configuration import config, vHUMAN
from xnu import kern, header, lldb_command, lldb_type_summary


@header(f"{'Task': <20s} {'PID': <8s} {'Name': <30s} {'Conclave': <20s} {'Conclave name': <60s} {'State': <15s}")
def GetAllConclavesSummary(t):
    """ Summarizes the important fields regarding to conclaves.
        params: task: value - value object representing a task in kernel
        returns: str - summary of all conclaves
    """
    out_str  = f"{t:<#20x}"

    proc     = GetProcFromTask(t)
    p_pid = proc.p_pid if proc is not None else ""
    p_comm = proc.p_comm if proc is not None else ""

    resource = Cast(t.conclave, 'exclaves_resource_t *')
    state    = GetEnumName('conclave_state_t',    resource.r_conclave.c_state, 'CONCLAVE_S_')
    
    out_str += f"{p_pid:<8} {p_comm:<30s}" f"{t.conclave:<#20x} {resource.r_name:<60s} {state:<15s}"

    return out_str


# Macro: showallconclaves
@lldb_command('showallconclaves', fancy=True)
def ShowAllConclaves(cmd_args=None, cmd_options={}, O=None):
    """ Iterate over all the tasks and show the tasks that have conclaves attached to them.

        Usage: showallconclaves
    """

    with O.table(GetAllConclavesSummary.header):
        for t in kern.tasks:
            if not hasattr(t, 'conclave'):
                print("The system does not support exclaves")
                return
            if t.conclave:
                print(GetAllConclavesSummary(t))
# EndMacro: showallconclaves


# Macro: showexclavesresourcetable
@lldb_command('showexclavesresourcetable', "D:")
def ShowExclavesResourceTable(cmd_args=None, cmd_options={}):
    """ Print all resources in all domains the roottable contains

        Usage: showexclavesresourcetable [-D <domain>]
               -D domain  : the name of the domain. e.g. "com.apple.kernel"
    """

    domain_tbl = kern.GetGlobalVariable('root_table')
    try:
        domain_heads = Cast(domain_tbl.t_buckets, 'queue_chain_t *')
    except AttributeError:
        print("The system does not support exclaves")
        return

    for domain_idx in range(int(domain_tbl.t_buckets_count)):
        for elem in IterateLinkageChain(addressof(domain_heads[domain_idx]), 'table_item_t *', 'i_chain'):
            domain = Cast(elem.i_value, 'exclaves_resource_domain_t *')

            if "-D" in cmd_options:
                if str(domain.d_name) != cmd_options['-D']:
                    continue

            tbl_loc   = Cast(domain.d_table_name, 'queue_chain_t *')
            entry_tbl = Cast(tbl_loc,             'table_t *')

            d_name_ = f"{VT.Bold}{str(domain.d_name)}{VT.EndBold}"
            out = (
                f"domain:{domain:<#x} d_name:{d_name_} "
                f"d_table_name:{domain.d_table_name:<#x} d_table_id:{domain.d_table_id:<#x}"
            )

            if config['verbosity'] > vHUMAN :
                out = f"domain-{domain_idx} " + out
            print(f"\n{out}")
            print("---------------------------------------------------------------")
            
            out = f"{'Entry':<5s} {'Resource': <20s} {'Name':<60s} {'Type':<25s} {'Id':<9s} {'Port':<20s} {'Connected':<10s}"
            if config['verbosity'] > vHUMAN :
                out += f"{'Elem': <19s} {'i_key': <19s} {'Len': <3s} {'i_value': <19s}"
            print(out)

            entry_heads = Cast(entry_tbl.t_buckets, 'queue_chain_t *')
            for entry_idx in range(int(entry_tbl.t_buckets_count)):
                for elem in IterateLinkageChain(entry_heads[entry_idx], 'table_item_t *', 'i_chain'):
                    resource = Cast(elem.i_key, 'exclaves_resource_t *')

                    state  = GetEnumName('conclave_state_t',        resource.r_conclave.c_state, 'CONCLAVE_S_')
                    r_type = GetEnumName('xnuproxy_resourcetype_s', resource.r_type,             'XNUPROXY_RESOURCETYPE_')
                    connected = "yes" if resource.r_connected else "no"

                    out = (
                        f"{entry_idx:<5} {resource:<#20x} {resource.r_name:<60s} {r_type:<25s} "
                        f"{resource.r_id:<#9x} {resource.r_port:<#20x} {connected:<10s}"
                    )
                    if config['verbosity'] > vHUMAN :
                        out += f"{elem:<#19x} {elem.i_key:<#19x} {elem.i_key_len:<3} {elem.i_value:<#19x}"
                    print(out)
# EndMacro: showexclavesresourcetable

@lldb_type_summary(['esync_t'])
@header("{0: <20s} {1: <10s} {2: <20s} {3: <20s}".format("esync_t", "id", "policy", "turnstile"))
def GetEsyncSummary(esync):
    """ Summarizes esync data structure
        params: esync: value - value object representing esync structure
        returns: str - summary of the esync object
    """
    format_string = "{0: <#020x} {1: <#010x} {2: <20s} {3: <#20x}"
    return format_string.format(esync, esync.es_id, GetEnumName('esync_policy_t', esync.es_policy), esync.es_turnstile)

@lldb_command('showesynctable', fancy=True)
def ShowESyncTable(cmd_args=None, cmd_options={}, O=None):
    """ Display info about the specified epoch sync table
        Usage: showesynctable <ht_t>|<ht_t *>
        Example: showesynctable &exclaves_queue_ht
    """

    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed.")

    try:
        table = kern.GetValueAsType(cmd_args[0], 'ht_t')
        bucket = Cast(table.ht_bucket, 'ht_bucket_t *')
    except:
        table = kern.GetValueFromAddress(cmd_args[0], "ht_t *")
        bucket = Cast(table.ht_bucket, 'ht_bucket_t *')

    with O.table(GetEsyncSummary.header, indent=True):
        for idx in range(int(table.ht_size)):
            for elem in IterateLinkageChain(addressof(bucket[idx].htb_head), 'esync_t *', 'es_link'):
                print(GetEsyncSummary(elem))

    return
