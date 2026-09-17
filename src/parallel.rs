pub fn map<T: Send, R: Send>(items: Vec<T>, f: impl Fn(T) -> R + Sync) -> Vec<R> {
    let workers = std::env::var("WELD_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map_or(1, usize::from)
                .min(8)
        });
    if items.len() < 32 || workers == 1 {
        return items.into_iter().map(f).collect();
    }
    let chunk_size = items.len().div_ceil(workers);
    std::thread::scope(|scope| {
        let mut pending = items.into_iter();
        let mut handles = Vec::new();
        loop {
            let chunk: Vec<_> = pending.by_ref().take(chunk_size).collect();
            if chunk.is_empty() {
                break;
            }
            let f = &f;
            handles.push(scope.spawn(move || chunk.into_iter().map(f).collect::<Vec<_>>()));
        }
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("worker panicked"))
            .collect()
    })
}
