// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

/*! \mainpage SHE(Secure Hardware Extension) API
 *
 * This document is a software reference description of the API provided by the
 * Secure Enclave Library on i.MX8DXL and i.MX95 platforms for SHE solutions
 * \image latex she_control_logic.png
 */
/*! \page  History Revision History
 *
 * Revision       | date           | description
 * :------------: | :-------------:| :------------
 * 0.1 | Jan 13 2024  | Initial Draft
 */

/*! \page page1 General concepts related to the API
 * \tableofcontents
 * \section sec1 Session
 * The API must be initialized by a potential requestor by opening a session.
 * The session establishes a route (MU, DomainID...) between the requester and the SHE.
 * When a session is opened, the SHE returns a handle identifying the session to the requester.
 * \section sec2 Service flow
 * For a given category of services which require service handle, the requestor is expected to open
 * a service flow by invoking the appropriate SHE API.
 * The session handle, as well as the control data needed for the service flow, are provided as
 * parameters of the call.
 * Upon reception of the open request, the SHE allocates a context in which the session handle,as
 * well as the provided control parameters are stored and return a handle identifying the service
 * flow.\n
 * The context is preserved until the service flow, or the session, are closed by the user and it is
 * used by the SHE to proceed with the sub-sequent operations requested by the user on the service
 * flow.
 * \section sec4 Key store
 * A key store can be created by specifying the CREATE flag in the she_open_key_store_service API.
 * Please note that the created key store will be not stored in the NVM till a key is generated or
 * imported specyfing the "STRICT OPERATION" flag.\n
 * \section sec5 Implementation specificities
 * SHE API with common features are supported on i.MX8DXL and i.MX95.The details of supported
 * features per chip will be listed in the platform specifities.
 */
