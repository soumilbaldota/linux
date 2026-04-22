// SPDX-License-Identifier: GPL-2.0
/*
 * superfork/kvm.c — KVM VM and vCPU fd cloning for container duplication.
 *
 * Called from fd.c's superfork_sanitize_inherited_fds() when a KVM_VM or
 * KVM_VCPU fd is encountered in the cloned task's file table.
 */

#include <linux/file.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/printk.h>
#include <linux/superfork.h>
#include "internal.h"

#ifdef CONFIG_KVM

static int superfork_clone_kvm_memslots(struct kvm *src_kvm, struct kvm *dst_kvm)
{
	int as_id;
	int ret = 0;

	if (!src_kvm || !dst_kvm)
		return -EINVAL;

	mutex_lock(&src_kvm->slots_lock);
	for (as_id = 0; as_id < kvm_arch_nr_memslot_as_ids(src_kvm); as_id++) {
		struct kvm_memslots *slots = __kvm_memslots(src_kvm, as_id);
		struct kvm_memory_slot *slot;
		int bkt;

		kvm_for_each_memslot(slot, bkt, slots) {
			struct kvm_userspace_memory_region2 region;

			if (!slot->npages)
				continue;

			if (slot->flags & KVM_MEM_GUEST_MEMFD) {
				ret = -EOPNOTSUPP;
				goto out_unlock;
			}

			memset(&region, 0, sizeof(region));
			region.slot = ((u32)as_id << 16) | (u16)slot->id;
			region.flags = slot->flags;
			region.guest_phys_addr = (u64)slot->base_gfn << PAGE_SHIFT;
			region.memory_size = (u64)slot->npages << PAGE_SHIFT;
			region.userspace_addr = slot->userspace_addr;

			ret = kvm_superfork_set_memslot(dst_kvm, &region);
			if (ret)
				goto out_unlock;
		}
	}

out_unlock:
	mutex_unlock(&src_kvm->slots_lock);
	return ret;
}

int superfork_clone_kvm_vm_fd(struct files_struct *files,
			      unsigned int fd,
			      struct file *src_file,
			      struct mm_struct *new_mm,
			      struct tgid_clone_entry *tgid_entry)
{
	struct file *new_vm_file = NULL;
	struct kvm *src_kvm;
	struct kvm *new_kvm = NULL;
	unsigned long vm_type;
	int ret;

	if (!new_mm)
		return -EINVAL;

	src_kvm = src_file->private_data;
	if (!src_kvm)
		return -EINVAL;

	vm_type = kvm_superfork_get_vm_type(src_kvm);

	ret = kvm_superfork_create_vm_for_mm(new_mm, vm_type,
					     &new_vm_file, &new_kvm);
	if (ret)
		return ret;

	ret = superfork_clone_kvm_memslots(src_kvm, new_kvm);
	if (ret)
		goto out_put_new_vm;

	ret = kvm_superfork_prepare_vm(new_kvm, src_kvm);
	if (ret)
		goto out_put_new_vm;

	ret = superfork_replace_file_at(files, fd, new_vm_file);
	if (ret)
		goto out_put_new_vm;

	if (tgid_entry && tgid_entry->kvm_vm_count < SF_MAX_KVM_VMS_PER_PROC) {
		int idx = tgid_entry->kvm_vm_count++;
		tgid_entry->kvm_vms[idx].src_fd = fd;
		tgid_entry->kvm_vms[idx].src_vm_file = NULL;
		tgid_entry->kvm_vms[idx].new_vm_file = NULL;
		tgid_entry->kvm_vms[idx].src_kvm = src_kvm;
		tgid_entry->kvm_vms[idx].new_kvm = new_kvm;
	}

	/* Drop the temporary reference held by wrapper call sites. */
	fput(new_vm_file);
	return 0;

out_put_new_vm:
	fput(new_vm_file);
	return ret;
}

static struct sf_kvm_vm_map *superfork_find_kvm_vm_map(struct tgid_clone_entry *tgid_entry,
							struct kvm *src_kvm)
{
	int i;

	if (!tgid_entry || !src_kvm)
		return NULL;

	for (i = 0; i < tgid_entry->kvm_vm_count; i++) {
		if (tgid_entry->kvm_vms[i].src_kvm == src_kvm)
			return &tgid_entry->kvm_vms[i];
	}

	return NULL;
}

static void superfork_remap_kvm_vcpu_vma(struct mm_struct *new_mm,
					  struct file *src_file,
					  struct file *new_vcpu_file)
{
	VMA_ITERATOR(vmi, new_mm, 0);
	struct vm_area_struct *vma;
	int found = 0;

	int scanned = 0;

	mmap_write_lock(new_mm);
	for_each_vma(vmi, vma) {
		scanned++;
		if (vma->vm_file == src_file) {
			vma_set_file(vma, new_vcpu_file);
			zap_vma_pages(vma);
			found++;
		}
	}
	mmap_write_unlock(new_mm);

	if (!found)
		pr_warn("superfork: kvm_run VMA not found for vcpu fd remap\n");
}

int superfork_clone_kvm_vcpu_fd(struct files_struct *files,
				unsigned int fd,
				struct file *src_file,
				struct mm_struct *new_mm,
				struct tgid_clone_entry *tgid_entry)
{
	struct kvm_vcpu *src_vcpu;
	struct sf_kvm_vm_map *vm_map;
	struct file *new_vcpu_file = NULL;
	struct kvm_vcpu *new_vcpu = NULL;
	int ret;

	if (!tgid_entry)
		return -EINVAL;

	src_vcpu = src_file->private_data;
	if (!src_vcpu || !src_vcpu->kvm)
		return -EINVAL;

	vm_map = superfork_find_kvm_vm_map(tgid_entry, src_vcpu->kvm);
	if (!vm_map || !vm_map->new_kvm)
		return -ENOENT;

	ret = kvm_superfork_create_vcpu(vm_map->new_kvm, src_vcpu->vcpu_id,
					&new_vcpu_file, &new_vcpu);
	if (ret)
		return ret;

	/*
	 * Tell QEMU the ioctl was interrupted by a signal so it loops back
	 * and re-issues KVM_RUN rather than treating exit_reason=0 as an
	 * unknown hardware exit and stopping the VM.
	 *
	 * KVM_EXIT_INTR means "ioctl(KVM_RUN) returned -EINTR" — QEMU handles
	 * it by re-entering the KVM_RUN loop immediately.  The paired fix is
	 * in superfork_copy_thread: if the vCPU thread has a valid vcpu_snap,
	 * the clone's pt_regs are set so iret lands back at the 'syscall'
	 * instruction for KVM_RUN rather than at wherever the thread was parked.
	 */
	new_vcpu->run->exit_reason = KVM_EXIT_INTR;

	ret = kvm_superfork_copy_vcpu_state(new_vcpu, src_vcpu);
	if (ret)
		goto out_put_new_vcpu;

	ret = superfork_replace_file_at(files, fd, new_vcpu_file);
	if (ret)
		goto out_put_new_vcpu;

	if (new_mm)
		superfork_remap_kvm_vcpu_vma(new_mm, src_file, new_vcpu_file);
	else
		pr_warn("superfork: skipping VMA remap: new_mm is NULL\n");

	if (vm_map->vcpu_count < SF_MAX_KVM_VCPUS_PER_VM) {
		int idx = vm_map->vcpu_count++;
		vm_map->vcpus[idx].src_fd = fd;
		vm_map->vcpus[idx].vcpu_id = src_vcpu->vcpu_id;
		vm_map->vcpus[idx].new_file = NULL;
		vm_map->vcpus[idx].new_vcpu = new_vcpu;
	}

	fput(new_vcpu_file);
	return 0;

out_put_new_vcpu:
	fput(new_vcpu_file);
	return ret;
}

#endif /* CONFIG_KVM */
