/*
 *
 *    Rev:          $Id: Readme.txt 1361 2005-09-28 17:22:20Z hennerich $
 *    Revision:     $Revision: 1361 $
 *    Source:       $Source$
 *    Created:      28.09.2005 19:06
 *    Author:       Michael Hennerich
 *    mail:         hennerich@blackfin.uclinux.org
 *    Description:  Master Slave SPI mode test application
 *
 *   Copyright (C) 2005 Michael Hennerich
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 ****************************************************************************
 * MODIFICATION HISTORY:
 ****************************************************************************


Master Slave SPI mode test application:

Note: This application may not work on BF533 STAMP,
      since SPISS (PF0) is used and routed to the CPLD.

Master Slave Connection Matrix:

    Master  <-->    Slave:

    SPISEL2 --> SPISS
    SPI_CLK --> SPI_CLK
    MOSI    --> MOSI
    MISO    <-- MISO

Test application usage:

    spi_test [-h?vsc] [-c count] message string
            -h?            this help
            -v             print version info
            -s             slave mode operation
            -c count       slave mode operation receive count

Example:

Master:

    root:~> spi_test 'Test 123'
    Set slave receive count to 8 bytes
    Last TX msg: Test 123
    root:~>

Slave :

    root:~> spi_test -s -c 8
    Waiting to receive 8 bytes from SPI Master
    Last RX msg: Test 123
    root:~>
