//! See https://github.com/aya-rs/aya/pull/70, but aya-ebpf doesn't support map
//! of maps though the PR has been open for 3 years, so just write our own

use core::{cell::UnsafeCell, marker::PhantomData, mem};

use aya_ebpf::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_HASH_OF_MAPS},
    helpers::bpf_map_lookup_elem,
};

#[repr(transparent)]
pub struct HashOfMaps<K, V> {
    def: UnsafeCell<bpf_map_def>,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

unsafe impl<K: Sync, V: Sync> Sync for HashOfMaps<K, V> {}

impl<K, V> HashOfMaps<K, V> {
    pub const fn with_max_entries(max_entries: u32) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_HASH_OF_MAPS,
                key_size: mem::size_of::<K>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: 0,
                id: 0,
                pinning: 0, //PinningType::None as u32,
            }),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    // pub const fn pinned(max_entries: u32, flags: u32) -> Self {
    //     Self {
    //         def: bpf_map_def {
    //             type_: BPF_MAP_TYPE_HASH_OF_MAPS,
    //             key_size: mem::size_of::<K>() as u32,
    //             value_size: mem::size_of::<u32>() as u32,
    //             max_entries,
    //             map_flags: flags,
    //             id: 0,
    //             pinning: 1, //PinningType::ByName as u32,
    //         },
    //         _k: PhantomData,
    //         _v: PhantomData,
    //     }
    // }

    pub unsafe fn get(&self, key: &K) -> Option<&V> {
        let value = bpf_map_lookup_elem(self.def.get() as *mut _, key as *const K as *const _);
        if value.is_null() {
            None
        } else {
            Some(&*(value as *const u32 as *const V))
        }
    }
}
