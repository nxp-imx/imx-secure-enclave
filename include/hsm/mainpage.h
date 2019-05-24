/*! \mainpage HSM API
 *
 * This document is a software referece description of the API provided by the i.MX8 HSM solutions.
 */ 

/*! \page  History Revision History
 * 
 * Revision 0.1: 29/03/2019 Savari preliminary draft - subject to change \n
 * Revision 0.8: 25/05/2019 Secondary draft - subject to change. It adds following APIs:
 *  - Signature generation, signature verification, rng, hash service flows and operations. 
 *  - Butterfly key expansion, ECIES enc/dec, public key reconstruction, public key decompression operations.
 * 
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


