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
 * 1.0 - subject to change | May 29 2019  | 
 */

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
 */


