package ui

import (
	"io"
	"log/slog"
	"net/http"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc"
)

// fileBasedPoolDriver reports whether a pool driver exposes a browsable file
// directory (mirrors grpcapi.isFileBasedDriver).
func fileBasedPoolDriver(driver string) bool {
	switch strings.ToLower(driver) {
	case "", "local", "dir", "nfs", "btrfs":
		return true
	}
	return false
}

// handleISOBrowserModal renders the ISO picker: the ISO libraries the caller
// may use (ListISOs — project libraries, then the global one), each picked as
// its pool/file.iso reference, and below them the storage content browser for
// browsing or uploading into a pool. The opener passes
// ?field=<input-name> so we can target the right input on selection.
func (s *Server) handleISOBrowserModal(w http.ResponseWriter, r *http.Request) {
	field := r.URL.Query().Get("field")
	if field == "" {
		field = "iso"
	}
	pools, _ := s.grpc.ListStoragePools(s.uiBearerCtx(r), &pb.ListStoragePoolsRequest{})
	var fp []*pb.StoragePool
	for _, p := range pools.GetPools() {
		if fileBasedPoolDriver(p.Driver) {
			fp = append(fp, p)
		}
	}
	data := map[string]any{"Pools": fp, "Field": field}
	if isos, err := s.grpc.ListISOs(s.uiBearerCtx(r), &pb.ListISOsRequest{Host: r.URL.Query().Get("host")}); err != nil {
		data["ISOError"] = err.Error()
	} else {
		data["ISOs"] = isos.GetIsos()
	}
	s.renderFragment(w, "iso_browser_modal.html", data)
}

// handleStorageContents renders the file list of one pool. poolref is
// "host::pool" (the browser's pool selector encodes both). Reused by the ISO
// picker and the pool contents view.
func (s *Server) handleStorageContents(w http.ResponseWriter, r *http.Request) {
	host, pool, _ := strings.Cut(r.URL.Query().Get("poolref"), "::")
	field := r.URL.Query().Get("field")
	if field == "" {
		field = "iso"
	}
	s.renderPoolContents(w, r, host, pool, field)
}

// renderPoolContents renders the file list for one pool (or a prompt when no
// pool is chosen).
func (s *Server) renderPoolContents(w http.ResponseWriter, r *http.Request, host, pool, field string) {
	if pool == "" {
		s.renderFragment(w, "storage_contents.html", map[string]any{"Field": field})
		return
	}
	resp, err := s.grpc.ListStoragePoolContents(s.uiBearerCtx(r), &pb.ListStoragePoolContentsRequest{PoolName: pool, Host: host})
	if err != nil {
		s.renderFragment(w, "storage_contents.html", map[string]any{"Field": field, "Error": err.Error()})
		return
	}
	s.renderFragment(w, "storage_contents.html", map[string]any{
		"Field": field, "Contents": resp.GetContents(), "Pool": pool, "Host": host,
	})
}

// handleUploadStorageContent streams an uploaded file (multipart) into a pool
// via the client-streaming UploadStoragePoolContent RPC, then re-renders the
// pool's file list. The form orders hidden fields before the file input so we
// know host/pool by the time we reach the file part.
func (s *Server) handleUploadStorageContent(w http.ResponseWriter, r *http.Request) {
	mr, err := r.MultipartReader()
	if err != nil {
		sendToast(w, "Upload failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var host, pool, field string
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			sendToast(w, "Upload failed: "+err.Error(), "error")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch part.FormName() {
		case "host":
			host = readPartString(part)
		case "pool":
			pool = readPartString(part)
		case "field":
			field = readPartString(part)
		case "file":
			filename := part.FileName()
			if filename == "" {
				continue
			}
			if uerr := s.streamUpload(r, host, pool, filename, part); uerr != nil {
				// A non-2xx is not swapped into the pool list, so the reason
				// travels in the toast, which htmx fires whatever the status.
				slog.Error("ui: pool upload", "pool", pool, "file", filename, "error", uerr)
				rpcWriteFailed(w, "Upload of "+filename, uerr)
				return
			}
			sendToast(w, "Uploaded "+filename, "success")
		}
	}
	if field == "" {
		field = "iso"
	}
	s.renderPoolContents(w, r, host, pool, field)
}

// streamUpload pumps an uploaded file into the pool over the gRPC client stream.
func (s *Server) streamUpload(r *http.Request, host, pool, filename string, src io.Reader) error {
	up, err := s.grpc.UploadStoragePoolContent(s.uiBearerCtx(r))
	if err != nil {
		return err
	}
	if err := up.Send(&pb.UploadStoragePoolContentRequest{PoolName: pool, Host: host, Filename: filename}); err != nil {
		return uploadSendFailed(up, err)
	}
	buf := make([]byte, 1<<20) // 1 MiB chunks
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if err := up.Send(&pb.UploadStoragePoolContentRequest{Chunk: buf[:n]}); err != nil {
				return uploadSendFailed(up, err)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	_, err = up.CloseAndRecv()
	return err
}

// uploadSendFailed returns the real reason a Send on the upload stream failed.
// grpc-go reports a stream the server has already ended — a refusal included —
// as io.EOF from Send and delivers the status only from CloseAndRecv, so
// passing the io.EOF on would toast "EOF" for a permission denial and answer
// it 500 instead of 403.
func uploadSendFailed(up grpc.ClientStreamingClient[pb.UploadStoragePoolContentRequest, pb.UploadStoragePoolContentResponse], err error) error {
	if err != io.EOF {
		return err
	}
	if _, rerr := up.CloseAndRecv(); rerr != nil {
		return rerr
	}
	return err
}

func readPartString(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 4096))
	return strings.TrimSpace(string(b))
}
