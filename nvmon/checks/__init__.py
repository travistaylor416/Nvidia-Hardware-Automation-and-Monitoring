"""Point-in-time health checks (PASS/WARN/FAIL per device)."""


def run_device_checks(device, settings, include_admin_down=False, max_diag=None, only_ports=None):
    if device.is_switch:
        from .switch import run_switch_checks
        return run_switch_checks(device, settings, include_admin_down=include_admin_down,
                                 max_diag=max_diag, only_ports=only_ports)
    from .server import run_server_checks
    return run_server_checks(device, settings)
