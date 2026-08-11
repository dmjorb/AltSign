//
//  native_bridge_zip.c
//  AltSign
//
//  Created by Magesh K on 25/02/26.
//

#include "native_bridge_zip.h"

#include "mz.h"
#include "mz_os.h"
#include "mz_strm.h"
#include "mz_zip.h"
#include "mz_zip_rw.h"

#include <string.h>

/* ---------- unzip ---------- */

native_bridge_unzFile native_bridge_unzOpen(const char *path)
{
    void *reader = mz_zip_reader_create();
    if (!reader) return NULL;
    if (mz_zip_reader_open_file(reader, path) != MZ_OK) {
        mz_zip_reader_delete(&reader);
        return NULL;
    }
    return (native_bridge_unzFile)reader;
}

int native_bridge_unzClose(native_bridge_unzFile file)
{
    void *reader = (void *)file;
    if (!reader) return -1;
    mz_zip_reader_close(reader);
    mz_zip_reader_delete(&reader);
    return 0;
}

int native_bridge_unzGetGlobalInfo(native_bridge_unzFile file, void *info)
{
    return 0;
}

int native_bridge_unzGoToFirstFile(native_bridge_unzFile file)
{
    void *reader = (void *)file;
    if (!reader) return -1;
    return mz_zip_reader_goto_first_entry(reader) == MZ_OK ? 0 : -1;
}

int native_bridge_unzGoToNextFile(native_bridge_unzFile file)
{
    void *reader = (void *)file;
    if (!reader) return -1;
    return mz_zip_reader_goto_next_entry(reader) == MZ_OK ? 0 : -1;
}

int native_bridge_unzGetCurrentFileInfo(
    native_bridge_unzFile file,
    void *info,
    char *filename,
    unsigned long filenameBufferSize)
{
    void *reader = (void *)file;
    if (!reader) return -1;
    mz_zip_file *file_info = NULL;
    if (mz_zip_reader_entry_get_info(reader, &file_info) != MZ_OK || !file_info) {
        return -1;
    }
    if (filename && filenameBufferSize > 0 && file_info->filename) {
        strncpy(filename, file_info->filename, filenameBufferSize - 1);
        filename[filenameBufferSize - 1] = '\0';
    }
    return 0;
}

int native_bridge_unzOpenCurrentFile(native_bridge_unzFile file)
{
    void *reader = (void *)file;
    if (!reader) return -1;
    return mz_zip_reader_entry_open(reader) == MZ_OK ? 0 : -1;
}

int native_bridge_unzReadCurrentFile(native_bridge_unzFile file, void *buffer, unsigned len)
{
    void *reader = (void *)file;
    if (!reader) return -1;
    return mz_zip_reader_entry_read(reader, buffer, (int32_t)len);
}

int native_bridge_unzCloseCurrentFile(native_bridge_unzFile file)
{
    void *reader = (void *)file;
    if (!reader) return -1;
    return mz_zip_reader_entry_close(reader) == MZ_OK ? 0 : -1;
}

/* ---------- zip ---------- */

native_bridge_zipFile native_bridge_zipOpen(const char *path)
{
    void *writer = mz_zip_writer_create();
    if (!writer) return NULL;
    if (mz_zip_writer_open_file(writer, path, 0, 0) != MZ_OK) {
        mz_zip_writer_delete(&writer);
        return NULL;
    }
    return (native_bridge_zipFile)writer;
}

int native_bridge_zipOpenNewFileInZip(native_bridge_zipFile file, const char *filename)
{
    return native_bridge_zipOpenNewFileInZipWithPermissions(file, filename, 0);
}

int native_bridge_zipOpenNewFileInZipWithPermissions(native_bridge_zipFile file, const char *filename, uint32_t permissions)
{
    void *writer = (void *)file;
    if (!writer) return -1;

    mz_zip_file file_info;
    memset(&file_info, 0, sizeof(file_info));
    file_info.filename = filename;
    file_info.external_fa = permissions << 16;
    file_info.compression_method = MZ_COMPRESS_METHOD_DEFLATE;

    return mz_zip_writer_entry_open(writer, &file_info) == MZ_OK ? 0 : -1;
}

int native_bridge_zipWriteInFileInZip(native_bridge_zipFile file, const void *buffer, unsigned len)
{
    void *writer = (void *)file;
    if (!writer) return -1;
    if (len == 0) return 0;
    int32_t written = mz_zip_writer_entry_write(writer, buffer, (int32_t)len);
    return written == (int32_t)len ? 0 : -1;
}

int native_bridge_zipCloseFileInZip(native_bridge_zipFile file)
{
    void *writer = (void *)file;
    if (!writer) return -1;
    return mz_zip_writer_entry_close(writer) == MZ_OK ? 0 : -1;
}

int native_bridge_zipClose(native_bridge_zipFile file)
{
    void *writer = (void *)file;
    if (!writer) return -1;
    mz_zip_writer_close(writer);
    mz_zip_writer_delete(&writer);
    return 0;
}

uint32_t native_bridge_unzGetCurrentFileExternalAttributes(native_bridge_unzFile file)
{
    void *reader = (void *)file;
    if (!reader) return 0;
    mz_zip_file *file_info = NULL;
    if (mz_zip_reader_entry_get_info(reader, &file_info) == MZ_OK && file_info) {
        return file_info->external_fa;
    }
    return 0;
}

