//! Selection shared by registered signing-key tables.

/// Selects one item, distinguishing empty, unnamed, missing, and ambiguous
/// requests through constructors supplied by the caller.
pub fn select<T, N, E>(
    items: impl IntoIterator<Item = T>,
    requested: Option<N>,
    matches: impl Fn(&N, &T) -> bool,
    empty: impl FnOnce() -> E,
    unnamed: impl FnOnce(usize) -> E,
    no_match: impl FnOnce(N) -> E,
    ambiguous: impl FnOnce(N) -> E,
) -> Result<T, E> {
    let items: Vec<T> = items.into_iter().collect();
    let count = items.len();
    if count == 0 {
        return Err(empty());
    }
    let Some(requested) = requested else {
        return match <[T; 1]>::try_from(items) {
            Ok([only]) => Ok(only),
            Err(_) => Err(unnamed(count)),
        };
    };
    let mut matching = items.into_iter().filter(|item| matches(&requested, item));
    let Some(found) = matching.next() else {
        return Err(no_match(requested));
    };
    if matching.next().is_some() {
        return Err(ambiguous(requested));
    }
    Ok(found)
}
