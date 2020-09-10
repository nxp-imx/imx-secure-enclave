/*! \mainpage SHE API
 *
 * This document is a software referece description of the API provided by the i.MX8 SHE solutions.
 */ 

/*! \page  History Revision History
 * 
 * Revision       | date           | description
 * :------------ | :-------------:| :------------
 * 0.5 | Mai 03 2019  | first draf
 * 1.0 | June 28 2019 | complete functions definition
 * 1.1 | December 20 2019 | add she_cmd_load_key_ext API
 * 1.2 | September 10 2020 | add she_storage_create_ext and she_cmd_verify_mac_bit_ext API
 */

/*! \page General General concepts related to the API
 */

/*! \page General
 * \section Session Session
 * The API must be initialized by a potential requestor by opening a session.\n
 * The session establishes a route (MU, DomainID...) between the requester and the SHE module, and grants the usage of a
 * specified key store.
 * When a session is opened, the SHE module returns a handle identifying the session to the requester.
 * 
 */


