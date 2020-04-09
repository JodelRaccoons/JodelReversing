import { Component } from "@angular/core";
import { UploadChangeParam, UploadFile } from "ng-zorro-antd";

export interface UploadResponse {
  package: string;
  version_name: string;
  version_code: string;
  signature_verified: boolean;
  is_jodel_signature: boolean;
  certs: string;
  hmac_key: string;
  key_status: { working: boolean };
  error: false;
  message: string;
}

@Component({
  selector: "app-root",
  templateUrl: "./app.component.html",
  styleUrls: ["./app.component.less"]
})
export class AppComponent {
  successfulExtraction = false;
  extractionData: UploadResponse;
  fileList: UploadFile[] = [];

  fileChange(uploadChangeParam: UploadChangeParam) {
    const { type, file, fileList } = uploadChangeParam;
    if (type === "success") {
      this.extractionData = file.response;
      this.successfulExtraction = true;
    } else {
      this.successfulExtraction = false;
      this.fileList = fileList.slice(-1);
    }
  }
}
