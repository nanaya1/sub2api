-- 尚未创建本地分组时也保留外部身份的删除墓碑，防止在途旧同步请求复活
-- 外键和已有映射保留，只有墓碑的 local_group_id 可以为空
ALTER TABLE provisioning_group_bindings ALTER COLUMN local_group_id DROP NOT NULL;
