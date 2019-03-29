/*! \mainpage
 *
 * This document is a software referece description of the API provided by the i.MX8 HSM solutions.
 */ 

/*! \page History Revision History
 *
 * Revision 0.1: 29/03/2019 Savari preliminary draft - subject to change
 */

/*! \page General General concepts related to the API
 */

/*! \page General
 * \section Session Session
 * The API must be initialized by a potential requestor by opening a session.\n
 * The session establishes a route (MU, DomainID...) between the requester and the HSM, and grants the usage of a specified key store through a password authentication.\n
 * When a session is opened, the HSM returns a handle identifying the session to the requester.
 * \section Service Service flow
 * For a given category of services, the requestor is expected to open a service flow by invoking the appropriate HSM API.
 * The session handle, as well as the control data needed for the service flow are provided as parameters of the call.
 * Upon reception of the open request, the HSM allocates a context in which the session handle, as well as the provided control parameters are stored.
 * The context is preserved until the service flow is closed by the user and it is used by the HSM to proceed with the sub-sequent operations requested by the user on the service flow.
 */
