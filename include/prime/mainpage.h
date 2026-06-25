// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

/*! \mainpage PRIME API
 *
 * This document is a software reference description of the API provided by the
 * Secure Enclave Library on i.MX937, i.MX941, i.MX942, i.MX943 and i.MX952 platforms
 * for V2X PRIME solutions
 */

/*! \page History Revision History
 *
 * Revision       | date           | description
 * :------------: | :-------------:| :------------
 * 0.1 | May 29 2026   | Initial Draft
 * 0.2 | July 14 2026  | Updated supported platforms list
 */

/*! \page page1 General concepts related to the API
 * \tableofcontents
 * \section sec1 Basic Concept
 * The UIO framework generates a set of directories and attribute files in sysfs.
 * These sysfs attributes allow searching for devices, finding the correct size
 * of the memory mappings.
 * \image latex prime_general_concept.png
 *
 * \section sec2 Session
 * The API must be initialized by a potential requestor by opening a session.
 * The session establishes a route between the requester and the PRIME.
 * When a session is opened, the PRIME returns a handle identifying the session to
 * the requester.
 *
 * \section sec3 PRIME Flow
 * \image latex prime_flow.png
 *
 * -# Initialization
 *    - The PRIME library initializes the PRIME hardware.
 *    - The library sets up the Mailbox driver.
 * -# Request Submission
 *    - Cryptographic operations are defined using PRIME Requests.
 *    - PRIME requests specify the operations to be performed, input data, and output buffers.
 *    - Requests are submitted to the PRIME hardware via mailbox.
 *    - If any error occurs during parameter validation or while pushing the requests,
 *      then the complete operation will be nacked with error.
 * -# Processing
 *    - The PRIME hardware reads the request and processes the cryptographic operations.
 *    - It uses DMA engines to read input data and write results to output buffers.
 *    - The hardware performs the specified cryptographic operations (e.g., encryption, hashing).
 * -# Completion
 *    - Once the operations are completed, the results are written to the output buffers.
 *    - The driver retrieves the results and notifies the application of job completion.
 *    - Job completion result is shared in the u32_t status_buffer, provided by the user itself.
 *    - In case of success, status_buffer will have (0xD6) and in case of failure (0x29).
 */

/*! \page page2 User space MU driver
 * User space application opens the UIO device file and mmap the Mailbox memory region
 * directly to user-space memory. This allows the user-space application to directly
 * read/write the message from user space. Data buffers can be managed and accessed
 * directly by the application without overhead of a copy.
 * \image latex prime_mu_driver.png
 */

/*! \page page3 ATU with PRIME
 * \image latex prime_atu_flow.png
 *
 * ATU_V2X (Address Translation Unit for V2X) is a hardware block that maps the V2X
 * subsystem's local DMA address space to SoC physical DRAM.
 *
 * \section sec5_1 RX Path (Hardware → Memory → CPU)
 *
 * -# V2X PHY receives data
 * -# V2X DMA writes to local address 0x0002_0000
 * -# ATU_V2X translates to DRAM address 0x9002_0000
 * -# DDR write occurs
 * -# CPU later reads buffer
 *
 * \section sec5_2 TX Path (CPU → Memory → Hardware)
 *
 * -# CPU writes packet to DRAM buffer
 * -# Clean cache
 * -# V2X DMA reads local address 0x0003_0000
 * -# ATU_V2X translates to DRAM
 * -# Packet transmitted
 *
 * \section sec5_3 ATU Configuration
 * ATU_V2X never touches caches. A hybrid approach is used to configure ATU:
 * -# User can provide its own physical address and size to configure ATU
 *    (maximum 1 GB supported) - not recommended.
 * -# User can request SE library to allocate physical address and size
 *    (maximum 1 GB supported) - recommended approach.
 *
 * \section sec5_4 Data Flow for User Allocated Memory with ATU
 * \image latex user_memory_allocation_atu_flow.png
 *
 * \section sec5_5 Data Flow for SE Allocated Memory with ATU
 * \image latex se_memory_allocation_atu_flow.png
 */
