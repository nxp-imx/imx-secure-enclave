/*! \mainpage HSM API
 *
 * This document is a software referece description of the API provided by the i.MX8 HSM solutions.
 */ 

/*! \page  History Revision History
 * 
 * Revision       | date           | description
 * :------------: | :-------------:| :------------
 * 0.1 - subject to change | Mar 29 2019  | Preliminary draf
 * 0.8 - subject to change | May 24 2019  | It adds the following API: \n-signature generation \n-signature verification \n-rng \n-hash \n-butterfly key expansion \n-ECIES enc/dec \n-public key reconstruction \n-public key decompression
 * 0.9 - subject to change | May 28 2019  | Explicit addresses are replaced by pointers.
 * 1.0 - subject to change | May 29 2019  | - bug/typos fix. \n- Change HSM_SVC_KEY_STORE_FLAGS definition
 * 1.1 - subject to change | July 31 2019 | - hsm_butterfly_key_expansion argument definition: dest_key_identifier is now a pointer. \n- add error code definition. \n- improve argument comments clarity
 * 1.5 - subject to change | Sept 13 2019 | - manage key argument: fix padding size\n - butterfly key expansion: change argument definition\n- introduce public key recovery API
 * 1.6 - subject to change | Oct 14 2019  | - add Key store section in chapter 3\n- change key_info and flags definition, substitute key_type_ext with group_id\n- hsm_generate_key, hsm_manage_key, hsm_butterfly_key_expansion: change argument definition\n- hsm_manage_key: change argument definition\n- add hsm_manage_key_group API
 * 1.7 - subject to change | Dec 20 2019  | - add generic data storage API \n- add GCM and CMAC support\n- add support for AES 192/256 key size for all cipher algorithms\n - add root KEK export API\n - add key import functionality\n- add get info API
 * 1.8 - subject to change | Feb 21 2020  | - fix HSM_KEY_INFO_TRANSIENT definition: delete erroneous "not supported" comment
 * */

/*! \page page1 General concepts related to the API
  \tableofcontents
  \section sec1 Session
  The API must be initialized by a potential requestor by opening a session.\n
  The session establishes a route (MU, DomainID...) between the requester and the HSM.
  When a session is opened, the HSM returns a handle identifying the session to the requester.
  \section sec2 Service flow
  For a given category of services, the requestor is expected to open a service flow by invoking the appropriate HSM API.\n
  The session handle, as well as the control data needed for the service flow, are provided as parameters of the call.\n
  Upon reception of the open request, the HSM allocates a context in which the session handle, as well as the provided control parameters are stored and return a handle identifying the service flow.\n
  The context is preserved until the service flow, or the session, are closed by the user and it is used by the HSM to proceed with the sub-sequent operations requested by the user on the service flow.
  \section sec3 Key store
  A key store can be created by specifying the CREATE flag in the hsm_open_key_store_service API. Please note that the created key store will be not stored in the NVM till a key is generated/imported specyfing the STRICT OPERATION flag.\n
  Only symmetric and private keys are stored into the key store. Public keys can be exported during the key pair generation operation or recalculated through the hsm_pub_key_recovery API.\n
  Secret keys cannot be exported under any circumstances, while they can be imported in encrypted form.\n
  \subsection subsec2 Key management
  Keys are divided in groups, keys belonging to the same group are written/read from the NVM as a monolitic block.\n
  Up to 3 key groups can be handled in the HSM local memory (those immediatly available to perform crypto operation), while up to 1024 key groups can be handled in the external NVM and imported in the local memory as needed.\n
  If the local memory is full (3 key groups already reside in the HSM local memory) and a new key group is needed by an incoming user request, the HSM swaps one of the local key group with the one needed by the user request.\n
  A control of which key group should be kept in the local memory (cached) is provide through the manage_key_group API lock/unlock mechanism.\n
  As general concept, frequently used keys should be kept, when possible, in the same key group and locked in the local memory for performance optimization.\n
  \subsection subsec3 NVM writing
  All the APIs modyfing the content of the key store (key generation/management) provide a "STRICT OPERATION" flag. If the flag is set, the HSM triggers and export of the encrypted key group into the external NVM and blows one bit of the OTP monotonic counter.\n
  Any update to the key store must be considered as effective only after an operation specifing the flag "STRICT OPERATION" is aknowledged by the HSM. All the operations not specifying the "STRICT OPERATION" flags impact the HSM local memory only and will be lost in case of system reset\n
  Due to the limited monotonic counter size (QXPB0 up to 1620 update available), the user should, when possible, perform multiple udates before setting the "STRICT OPERATION" flag.\n
  Once the monotonic counter is completely blown a warning is returned on each update operation to inform the user that the new updates are not roll-back protected.
 */
