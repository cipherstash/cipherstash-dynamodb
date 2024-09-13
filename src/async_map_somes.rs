use std::future::Future;

/// Take an input vector and run a callback over only the Somes in the vec.
///
/// The callback must return a vector in the same order and equal in length to the Somes.
pub async fn async_map_somes<T, U, E, F: Future<Output = Result<Vec<U>, E>>>(
    input: Vec<Option<T>>,
    callback: impl FnOnce(Vec<T>) -> F,
) -> Result<Vec<Option<U>>, E> {
    let mut output = Vec::with_capacity(input.len());
    output.resize_with(input.len(), || None);

    let (indexes, somes): (Vec<usize>, Vec<T>) = input
        .into_iter()
        .enumerate()
        .filter_map(|(i, x)| x.map(|y| (i, y)))
        .unzip();

    let somes_len = somes.len();

    let callback_result = callback(somes).await?;

    assert_eq!(
        callback_result.len(),
        somes_len,
        "expected input length to equal output length"
    );

    for (x, i) in callback_result.into_iter().zip(indexes.into_iter()) {
        output[i] = Some(x);
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[should_panic]
    async fn test_array_different_size() {
        async_map_somes(vec![Some(10)], |_| async { Ok::<Vec<()>, ()>(vec![]) })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_maintain_order() {
        let input = vec![None, Some(1_u8), None, Some(2_u8), None, Some(3_u8)];

        let output = async_map_somes(input.clone(), |x| async { Ok::<_, ()>(x) })
            .await
            .unwrap();

        assert_eq!(input, output);
    }
}
