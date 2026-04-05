/* Copyright (C) 2015, monitoring agent Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef OS_WIN_H
#define OS_WIN_H

/* Install the Monitoring agent service */
int InstallService(char *path);

/* Uninstall the Monitoring agent service */
int UninstallService();

/* Check if the Monitoring agent service is running
 * Returns 1 on success (running) or 0 if not running
 */
int CheckServiceRunning();

/* Start Monitoring service */
int os_start_service();

/* Stop Monitoring service */
int os_stop_service();

/* Start the process from the services */
int os_WinMain(int argc, char **argv);

/* Locally start the process (after the services initialization) */
int local_start();

#endif /* OS_WIN_H */
