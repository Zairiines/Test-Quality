package com.example.demo.entity;

import org.springframework.web.multipart.MultipartFile;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

public class CustomFile implements MultipartFile {

    private final byte[] bytes;
    private final String originalFilename;


    public CustomFile(byte[] bytes, String originalFilename) {
        this.bytes = bytes;
        this.originalFilename = originalFilename;
    }

    @Override
    public String getOriginalFilename() {
        return originalFilename;
    }

    @Override
    public boolean isEmpty() {
        return bytes == null || bytes.length == 0;
    }

    @Override
    public long getSize() {
        return bytes.length;
    }

    @Override
    public byte[] getBytes() throws IOException {
        return bytes;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return new ByteArrayInputStream(bytes);
    }

	@Override
	public String getName() {
		return null ;
	}

	@Override
	public String getContentType() {
		return null;
	}

	@Override
	public void transferTo(File dest) throws IOException, IllegalStateException {
		
	}



}
