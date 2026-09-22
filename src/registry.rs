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
    select_split(
        items, requested, matches, empty, unnamed, no_match, ambiguous,
    )
    .0
}

/// Selects as [`select`] does and also returns the items left behind, so a
/// caller holding the only copy can rebuild itself from them.
pub fn select_split<T, N, E>(
    items: impl IntoIterator<Item = T>,
    requested: Option<N>,
    matches: impl Fn(&N, &T) -> bool,
    empty: impl FnOnce() -> E,
    unnamed: impl FnOnce(usize) -> E,
    no_match: impl FnOnce(N) -> E,
    ambiguous: impl FnOnce(N) -> E,
) -> (Result<T, E>, Vec<T>) {
    let mut items: Vec<T> = items.into_iter().collect();
    let count = items.len();
    if count == 0 {
        return (Err(empty()), items);
    }
    let Some(requested) = requested else {
        if count > 1 {
            return (Err(unnamed(count)), items);
        }
        let only = items.remove(0);
        return (Ok(only), items);
    };
    let mut matching = items
        .iter()
        .enumerate()
        .filter(|(_, item)| matches(&requested, item));
    let Some((index, _)) = matching.next() else {
        return (Err(no_match(requested)), items);
    };
    if matching.next().is_some() {
        return (Err(ambiguous(requested)), items);
    }
    let found = items.remove(index);
    (Ok(found), items)
}
