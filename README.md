# DNS-SD/Bonjour protocol support library

By default, advertises HTTP server (if enabled).

Additional insances can be added by user's application, example (for Apple HAP):

```c
const struct mgos_dns_sd_txt_entry gizmo_txt[] = {
    {.key = "c#", .value = "1"},
    {.key = "ff", .value = "0"},
    {.key = "pv", .value = "1.0"},
    {.key = "id", .value = "11:22:33:44:55:66"},
    {.key = "md", .value = "Fancy Gizmo 9000"},
    {.key = "s#", .value = "1"},
    {.key = "sf", .value = "1"},
    {.key = "ci", .value = "8"},  // Switch
    {.key = NULL},
};
mgos_dns_sd_add_service_instance("gizmo9000", "_hap._tcp", 8080, gizmo_txt);
```
