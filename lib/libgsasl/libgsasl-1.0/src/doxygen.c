/*! \mainpage GNU SASL Library
 *
 * \section intro Introduction
 *
 * GNU SASL is an implementation of the Simple Authentication and Security
 * Layer framework and a few common SASL mechanisms.  SASL is used by
 * network servers (e.g., IMAP, SMTP) to request authentication from
 * clients, and in clients to authenticate against servers.
 *
 * GNU SASL consists of a library (`libgsasl'), a command line utility
 * (`gsasl') to access the library from the shell, and a manual.  The
 * library includes support for the framework (with authentication
 * functions and application data privacy and integrity functions) and at
 * least partial support for the CRAM-MD5, EXTERNAL, GSSAPI, ANONYMOUS,
 * PLAIN, SECURID, DIGEST-MD5, LOGIN, and NTLM mechanisms.
 *
 * The library is easily ported because it does not do network
 * communication by itself, but rather leaves it up to the calling
 * application.  The library is flexible with regards to the authorization
 * infrastructure used, as it utilize a callback into the application to
 * decide whether a user is authorized or not.
 *
 * GNU SASL is developed for the GNU/Linux system, but runs on over 20
 * platforms including most major Unix platforms and Windows, and many
 * kind of devices including iPAQ handhelds and S/390 mainframes.
 *
 * GNU SASL is written in pure ANSI C89 to be portable to embedded and
 * otherwise limited platforms.  The entire library, with full support for
 * ANONYMOUS, EXTERNAL, PLAIN, LOGIN and CRAM-MD5, and the front-end that
 * support client and server mode, and the IMAP and SMTP protocols, fits
 * in under 60kb on an Intel x86 platform, without any modifications to
 * the code.  (This figure was accurate as of version 0.0.13.)
 *
 * The library is licensed under the GNU Lesser General Public License,
 * and the command-line interface, self-tests and examples are licensed
 * under the GNU General Public License.
 *
 *
 * The project web page:\n
 * http://www.gnu.org/software/gsasl/
 *
 * The software archive:\n
 * ftp://alpha.gnu.org/pub/gnu/gsasl/
 *
 * Further information and paid contract development:\n
 * Simon Josefsson <simon@josefsson.org>
 *
 * \section abstraction Logical overview
 *
 * \image html abstraction.png
 * \image latex abstraction.eps "Logical overview" width=10cm
 *
 * \section controlflow Control flow in application using the library
 *
 * \image html controlflow.png
 * \image latex controlflow.eps "Control flow" width=15cm

 * \image html controlflow2.png
 * \image latex controlflow2.eps "Control flow" width=16cm
 *
 * \section examples Examples
 *
 * \include client.c
 * \include client-serverfirst.c
 * \include client-mech.c
 * \include client-callback.c
 */
