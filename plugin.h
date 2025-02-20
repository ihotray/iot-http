#ifndef __PLUGIN_H__
#define __PLUGIN_H__

#include <iot/mongoose.h>

void http_plugin_load(void *handle);
void http_plugin_free(void *handle);
bool http_plugin_handler(struct mg_connection *c, int ev, void *ev_data, void *fn_data);

#endif