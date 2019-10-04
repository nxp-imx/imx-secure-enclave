/*! \mainpage HSM API
 *
 * This document is a software referece description of the API provided by the i.MX8 HSM solutions.
 */ 

/*! \page  History Revision History
 * 
 * Revision       | date           | description
 * :------------: | :-------------:| :------------
 * 0.1 - subject to change | Mar 29 2019  | Savari preliminary draf
 * 0.8 - subject to change | May 24 2019  | It adds the following API: \n-signature generation \n-signature verification \n-rng \n-hash \n-butterfly key expansion \n-ECIES enc/dec \n-public key reconstruction \n-public key decompression
 * 0.9 - subject to change | May 28 2019  | Explicit addresses are replaced by pointers.
 * 1.0 - subject to change | May 29 2019  | -bug/typos fix. \n-Change HSM_SVC_KEY_STORE_FLAGS definition
 * 1.1 - subject to change | July 31 2019 | -hsm_butterfly_key_expansion argument definition: dest_key_identifier is now a pointer. \n-Add error code definition. \n-improve argument comments clarity
 * 1.5 - subject to change | Sept 13 2019 | -manage key argument: fix padding size\n - butterfly key expansion: change argument definition\n- introduce public key recovery API
 * 1.6 - subject to change | Oct 14 2019  | -hsm_generate_key: change key_info and flags definition, substitute key_type_ext with group_id (mandatory when creating a new key)\n-hsm_open_key_store_service: remove HSM_SVC_KEY_STORE_FLAGS_DELETE flag
 * */

/*! \page General General concepts related to the API
 */

/*! \page General
 * \section Session Session
 * The API must be initialized by a potential requestor by opening a session.\n
 * The session establishes a route (MU, DomainID...) between the requester and the HSM.
 * When a session is opened, the HSM returns a handle identifying the session to the requester.
 *
 * \section Service Service flow
 * For a given category of services, the requestor is expected to open a service flow by invoking the appropriate HSM API.\n
 * The session handle, as well as the control data needed for the service flow, are provided as parameters of the call.\n
 * Upon reception of the open request, the HSM allocates a context in which the session handle, as well as the provided control parameters are stored and return a handle identifying the service flow.\n
 * The context is preserved until the service flow, or the session, are closed by the user and it is used by the HSM to proceed with the sub-sequent operations requested by the user on the service flow.
 *
 * \sectuib key store
 * The HSM key store handle only symmetric and private keys, the public keys are optionally exported during the key pair generation operation and can be recalculated through the hsm_pub_key_recovery function. \n
 * Key are divied in key_group, each group can contain till 100 ECC 256 bit keys. Once a key group is updated or a key part of a key group is used, the entire key group is copied in the HSM local memory. The HSM can handle maximum 3 key group in his local memory, other groups are handled in the NVM and copied in the local memory when needed with a penalty of time.
 * A lock flag is available to indicate to the HSM to always take a copy of the key group in the local memory, this lock can be reseted by the unlock flag or by a PoR.
 * 
 * /


