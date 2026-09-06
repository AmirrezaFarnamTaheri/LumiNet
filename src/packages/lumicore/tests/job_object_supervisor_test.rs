use lumicore::platform::job_object_supervisor::JobObjectSupervisor;

#[test]
fn test_job_object_supervisor_lifecycle() {
    let supervisor = JobObjectSupervisor::new().expect("Failed to create JobObjectSupervisor");

    // Spawn a dummy child process
    #[cfg(windows)]
    let mut child = std::process::Command::new("cmd")
        .args(["/c", "ping -n 5 127.0.0.1 >nul"])
        .spawn()
        .expect("Failed to spawn child process");

    #[cfg(not(windows))]
    let mut child = std::process::Command::new("sleep")
        .arg("5")
        .spawn()
        .expect("Failed to spawn child process");

    let child_pid = child.id();
    let assign_res = supervisor.assign_pid(child_pid);
    assert!(
        assign_res.is_ok(),
        "Failed to assign child PID to JobObjectSupervisor: {:?}",
        assign_res.err()
    );

    // Closing supervisor should kill child via job object limit and be idempotent
    supervisor.close();
    supervisor.close();

    // Clean up test child if needed
    let _ = child.kill();

    // After close, further assignments should return an error
    let second_assign = supervisor.assign_pid(child_pid);
    assert!(second_assign.is_err());
}

