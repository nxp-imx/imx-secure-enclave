// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

/*! \mainpage SHE API
 *
 * This document is a software referece description of the API provided by the i.MX8 SHE solutions.
 */ 

/*! \page  History Revision History
 * 
 * Revision       | date           | description
 * :------------ | :-------------:| :------------
 * 0.1 | Jul 06 2023  | first draft
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


