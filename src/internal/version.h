/*! \file   version.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  imquic versioning (headers)
 * \details This exposes a quick an easy way to display the commit the
 * compiled version of imquic implements, and when it has been built. It
 * is based on this excellent comment: http://stackoverflow.com/a/1843783
 *
 * \ingroup API Core
 */

#ifndef IMQUIC_VERSION_H
#define IMQUIC_VERSION_H

extern const char *imquic_name;
extern int imquic_version_major;
extern int imquic_version_minor;
extern int imquic_version_patch;
extern const char *imquic_version_release;
extern const char *imquic_version_string;
extern const char *imquic_version_string_full;
extern const char *imquic_build_git_time;
extern const char *imquic_build_git_sha;

#endif
