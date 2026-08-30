//
// Created by unnamedfurry on 8/30/26.
//

#include "shared-variables.h"

MYSQL *conn = nullptr;
ClientSession *activeClients = nullptr;
pthread_mutex_t mysql_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t clientsMutex = PTHREAD_MUTEX_INITIALIZER;
bool finishedResponse = false;