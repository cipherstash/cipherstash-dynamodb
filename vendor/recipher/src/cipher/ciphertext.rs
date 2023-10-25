pub(crate) type Block<const B: usize> = [u8; B];

#[derive(Debug)]
pub(crate) struct CipherText<const B: usize> {
    pub(crate) data: Vec<Block<B>>,
    pub(crate) block_count: usize,
}

impl<const B: usize> CipherText<B> {
    pub(crate) fn init(block_count: usize) -> Self {
        Self {
            data: vec![[0u8; B]; block_count + 1],
            block_count: block_count + 1,
        }
    }

    pub(crate) fn aont_key(&self) -> &Block<B> {
        &self.data[self.block_count - 1]
    }

    pub(crate) fn aont_key_mut(&mut self) -> &mut Block<B> {
        &mut self.data[self.block_count - 1]
    }

    pub(crate) fn blocks(&self) -> &[Block<B>] {
        &self.data[..(self.block_count - 1)]
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.data.iter().flatten().copied().collect()
    }

    pub(crate) fn from_bytes(input: &[u8]) -> Self {
        let data: Vec<Block<B>> = input
            .chunks(B)
            .map(|bytes| {
                let mut block = [0u8; B];
                block.copy_from_slice(bytes);
                block
            })
            .collect();

        let block_count = data.len();

        Self { data, block_count }
    }
}
