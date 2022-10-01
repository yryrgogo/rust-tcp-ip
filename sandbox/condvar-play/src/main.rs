use std::sync::{Arc, Condvar, Mutex};
use std::thread;

fn main() {
    let pair1 = Arc::new((Mutex::new(false), Condvar::new()));
    let pair2 = Arc::clone(&pair1);

    thread::spawn(move || {
        let (lock, cvar) = &*pair2;
        let mut started = lock.lock().unwrap();
        *started = true;

        cvar.notify_all();
    });

    let (lock, cvar) = &*pair1;
    let mut started = lock.lock().unwrap();

    println!("pair1 lock: {}", started);
    while !*started {
        started = cvar.wait(started).unwrap();
    }
    println!("pair1 lock: {}", started);
}
