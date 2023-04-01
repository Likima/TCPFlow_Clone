#include "packet_capture.h"

char* get_os_version(){
    struct utsname info;
    if (uname(&info) == -1) {
        fprintf(stderr, "Failed to get OS information.\n");
        return NULL;
    }
    return info.release;
    return 0;
}

char* get_os_release() {
    struct utsname info;
    if (uname(&info) == -1) {
        fprintf(stderr, "Failed to get OS information.\n");
        return NULL;
    }
    char* os_release = strdup(info.release);
    return os_release;
}

char* get_os_name() {
    struct utsname info;
    if (uname(&info) == -1) {
        fprintf(stderr, "Failed to get OS information.\n");
        return NULL;
    }
    char* os_name = malloc(sizeof(char) * (strlen(info.sysname) + strlen(info.release) + 2));
    sprintf(os_name, "%s %s", info.sysname, info.release);
    return os_name;
}
void initialize(){
    fprintf(fp, "<program>TCP_FLOW_CLONE</program>\n");
    fprintf(fp, "<OS_ENVIRONMENT>\n");
    fprintf(fp, "<operating_system>%s</operating_system>\n", get_os_name());
    fprintf(fp, "<os_version>%s</os_version>\n", get_os_version());
    fprintf(fp, "<os_release>%s</os_release>\n", get_os_release());
    fprintf(fp, "</OS_ENVIRONMENT>\n");
}