#include "es_bridge_darwin.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <stdlib.h>

extern void sentinelGoESEvent(
    uint32_t event_type,
    int32_t pid,
    int32_t ppid,
    const char *path,
    const char *old_path
);

struct sentinel_es_client {
  es_client_t *client;
};

static void handle_event(
    sentinel_es_client *state,
    const es_message_t *message
) {
  if (state == NULL || message == NULL) {
    return;
  }

  const es_process_t *process = message->process;

  if (process == NULL) {
    return;
  }

  int32_t pid = audit_token_to_pid(process->audit_token);
  int32_t ppid = process->ppid;

  switch (message->event_type) {

  // Normalized event type constants sent to Go (must match es_event.go):
  //   1 = esEventTypeCreate, 2 = esEventTypeWrite,
  //   3 = esEventTypeUnlink, 4 = esEventTypeRename

  case ES_EVENT_TYPE_NOTIFY_CREATE: {
    char pathbuf[4096];
    const char *path = NULL;

    if (message->event.create.destination_type ==
        ES_DESTINATION_TYPE_EXISTING_FILE) {
      path = message->event.create.destination.existing_file->path.data;
    } else if (message->event.create.destination_type ==
               ES_DESTINATION_TYPE_NEW_PATH) {
      const char *dir =
          message->event.create.destination.new_path.dir->path.data;
      const char *name =
          message->event.create.destination.new_path.filename.data;
      if (dir != NULL && name != NULL) {
        snprintf(pathbuf, sizeof(pathbuf), "%s/%s", dir, name);
        path = pathbuf;
      }
    }

    if (path == NULL) {
      return;
    }

    sentinelGoESEvent(1, pid, ppid, path, NULL);
    break;
  }

  case ES_EVENT_TYPE_NOTIFY_WRITE: {
    const char *path = message->event.write.target->path.data;

    if (path == NULL) {
      return;
    }

    sentinelGoESEvent(2, pid, ppid, path, NULL);
    break;
  }

  case ES_EVENT_TYPE_NOTIFY_UNLINK: {
    const char *path = message->event.unlink.target->path.data;

    if (path == NULL) {
      return;
    }

    sentinelGoESEvent(3, pid, ppid, path, NULL);
    break;
  }

  case ES_EVENT_TYPE_NOTIFY_RENAME: {
    const char *source = message->event.rename.source->path.data;

    char destbuf[4096];
    const char *destination = NULL;

    if (message->event.rename.destination_type ==
        ES_DESTINATION_TYPE_EXISTING_FILE) {
      destination =
          message->event.rename.destination.existing_file->path.data;
    } else if (message->event.rename.destination_type ==
               ES_DESTINATION_TYPE_NEW_PATH) {
      const char *dir =
          message->event.rename.destination.new_path.dir->path.data;
      const char *name =
          message->event.rename.destination.new_path.filename.data;
      if (dir != NULL && name != NULL) {
        snprintf(destbuf, sizeof(destbuf), "%s/%s", dir, name);
        destination = destbuf;
      }
    }

    sentinelGoESEvent(4, pid, ppid, destination, source);
    break;
  }

  default:
    break;
  }
}

int sentinel_es_client_create(
    sentinel_es_client **out_client
) {
  if (out_client == NULL) {
    return -1;
  }

  sentinel_es_client *state =
      calloc(1, sizeof(sentinel_es_client));

  if (state == NULL) {
    return -2;
  }

  es_new_client_result_t result =
      es_new_client(
          &state->client,
          ^(
              es_client_t *client,
              const es_message_t *message
          ) {
            (void)client;

            handle_event(state, message);
          }
      );

  if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
    free(state);
    return (int)result;
  }

  *out_client = state;

  return 0;
}

int sentinel_es_client_subscribe(
    sentinel_es_client *state
) {
  if (state == NULL || state->client == NULL) {
    return -1;
  }

  es_event_type_t events[] = {
    ES_EVENT_TYPE_NOTIFY_CREATE,
    ES_EVENT_TYPE_NOTIFY_WRITE,
    ES_EVENT_TYPE_NOTIFY_UNLINK,
    ES_EVENT_TYPE_NOTIFY_RENAME,
  };

  es_return_t result =
      es_subscribe(
          state->client,
          events,
          sizeof(events) / sizeof(events[0])
      );

  if (result != ES_RETURN_SUCCESS) {
    return (int)result;
  }

  return 0;
}

void sentinel_es_client_delete(
    sentinel_es_client *state
) {
  if (state == NULL) {
    return;
  }

  if (state->client != NULL) {
    es_delete_client(state->client);
    state->client = NULL;
  }

  free(state);
}