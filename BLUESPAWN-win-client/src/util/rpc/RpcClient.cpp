#include "util/rpc/RpcClient.h"

#include <util/StringUtils.h>
#include <util/Utils.h>

#include <sstream>

namespace RpcClient {
    protobuffer::Detection RpcClient::SerializeDetectionObject(IN CONST std::shared_ptr<Detection>& detection,
                                                               IN CONST RecordType type = RecordType::PostScan) {
        protobuffer::Detection message;
        message.set_id(detection->dwID);
        message.set_timestamp(FileTimeToInteger(detection->context.DetectionCreatedTime));
        message.set_type(static_cast<bluespawn::protobuffer::DetectionType>(detection->type));
        message.set_record_type(static_cast<bluespawn::protobuffer::DetectionRecordType>(type));

        protobuffer::ScanInfo info;
        info.set_certainty(detection->info.GetCertainty());
        info.set_raw_certainty(detection->info.GetIntrinsicCertainty());
        message.set_allocated_info(&info);

        protobuffer::DetectionData data;
        if(std::holds_alternative<ProcessDetectionData>(detection->data)) {
            ProcessDetectionData& processData = std::get<ProcessDetectionData>(detection->data);
            protobuffer::ProcessDetectionData pbProcessData;
            pbProcessData.set_type(static_cast<bluespawn::protobuffer::ProcessDetectionType>(processData.type));
            pbProcessData.set_pid(*processData.PID);
            pbProcessData.set_tid(*processData.TID);
            pbProcessData.set_process_name(WidestringToString(*processData.ProcessName));
            pbProcessData.set_process_path(WidestringToString(*processData.ProcessPath));
            pbProcessData.set_process_command(WidestringToString(*processData.ProcessCommand));
            std::wstringstream baseAddress{};
            baseAddress << std::hex << *processData.BaseAddress;
            pbProcessData.set_base_address(WidestringToString(baseAddress.str()));
            pbProcessData.set_memory_size(*processData.MemorySize);
            pbProcessData.set_image_name(WidestringToString(*processData.ImageName));
            data.set_allocated_process_data(&pbProcessData);
        } else if(std::holds_alternative<FileDetectionData>(detection->data)) {
            FileDetectionData fileData = std::get<FileDetectionData>(detection->data);
            protobuffer::FileDetectionData pbFileData;
            pbFileData.set_exists(fileData.FileFound);
            pbFileData.set_file_path(WidestringToString(fileData.FilePath));
            pbFileData.set_file_name(WidestringToString(fileData.FileName));
            pbFileData.set_file_extension(WidestringToString(*fileData.FileExtension));
            pbFileData.set_file_type(WidestringToString(*fileData.FileType));
            pbFileData.set_executor(WidestringToString(*fileData.Executor));
            pbFileData.set_md5(WidestringToString(*fileData.MD5));
            pbFileData.set_sha1(WidestringToString(*fileData.SHA1));
            pbFileData.set_sha256(WidestringToString(*fileData.SHA256));
            pbFileData.set_last_opened(FileTimeToInteger(*fileData.LastOpened));
            pbFileData.set_last_opened(FileTimeToInteger(*fileData.FileCreated));
            protobuffer::YaraScanResult pbYaraScanResult;
            if(fileData.yara.has_value()) {
                for(auto& str : fileData.yara.value().vKnownBadRules) {
                    pbYaraScanResult.add_known_bad_rules(WidestringToString(str));
                }
                for(auto& str : fileData.yara.value().vIndicatorRules) {
                    pbYaraScanResult.add_indicator_rules(WidestringToString(str));
                }
            }
            pbFileData.set_allocated_yara(&pbYaraScanResult);
            pbFileData.set_file_signed(*fileData.FileSigned);
            pbFileData.set_signer(WidestringToString(*fileData.Signer));
            data.set_allocated_file_data(&pbFileData);
        } else if(std::holds_alternative<RegistryDetectionData>(detection->data)) {
            RegistryDetectionData registryData = std::get<RegistryDetectionData>(detection->data);
            protobuffer::RegistryDetectionData pbRegistryData;
            pbRegistryData.set_key_path(WidestringToString(registryData.KeyPath));
            protobuffer::RegistryKey pbRegistryKey;
            pbRegistryKey.set_key_path(WidestringToString(registryData.key.GetName()));
            pbRegistryKey.set_exists(registryData.key.Exists());
            pbRegistryData.set_allocated_key(&pbRegistryKey);
            protobuffer::RegistryValue pbRegistryValue;
            pbRegistryValue.set_allocated_key(&pbRegistryKey);
            if(registryData.value.has_value()) {
                pbRegistryValue.set_value_name(WidestringToString((*registryData.value).wValueName));
                pbRegistryValue.set_value_data(WidestringToString((*registryData.value).ToString()));
            }
            pbRegistryData.set_allocated_value(&pbRegistryValue);
            pbRegistryData.set_type(static_cast<bluespawn::protobuffer::RegistryDetectionType>(registryData.type));
            data.set_allocated_registry_data(&pbRegistryData);
        } else if(std::holds_alternative<ServiceDetectionData>(detection->data)) {
            ServiceDetectionData serviceData = std::get<ServiceDetectionData>(detection->data);
            protobuffer::ServiceDetectionData pbServiceData;
            pbServiceData.set_service_name(WidestringToString(*serviceData.ServiceName));
            pbServiceData.set_display_name(WidestringToString(*serviceData.DisplayName));
            pbServiceData.set_description(WidestringToString(*serviceData.Description));
            pbServiceData.set_file_path(WidestringToString(*serviceData.FilePath));
            data.set_allocated_service_data(&pbServiceData);
        } else {
            OtherDetectionData otherData = std::get<OtherDetectionData>(detection->data);
            protobuffer::OtherDetectionData pbOtherData;
            pbOtherData.set_type(WidestringToString(otherData.DetectionType));
            auto mutable_properties = pbOtherData.mutable_properties();
            for(const auto& [key, value] : otherData.DetectionProperties) {
                mutable_properties->insert({ WidestringToString(key), WidestringToString(value) });
            }
        }
        message.set_allocated_data(&data);

        protobuffer::DetectionContext context;

        if(detection->context.hunts.size()) {
            for(const auto& hunt : detection->context.hunts) {
                context.add_hunts(WidestringToString(hunt));
            }
        }

        if(detection->context.FirstEvidenceTime) {
            context.set_first_evidence_time(FileTimeToInteger(*detection->context.FirstEvidenceTime));
        }

        context.set_first_evidence_time(FileTimeToInteger(detection->context.DetectionCreatedTime));

        if(detection->context.note) {
            context.set_note(WidestringToString(*detection->context.note));
        }

        message.set_allocated_context(&context);

        return message;
    }

    bool RpcClient::RpcClient::RecordDetection(IN const std::shared_ptr<Detection>& detection,
                                               IN CONST RecordType type) {
        auto request = SerializeDetectionObject(detection, type);

        protobuffer::ResponseMessage response;
        ClientContext context;

        Status status = stub_->RecordDetection(&context, request, &response);

        if(status.ok() && response.received()) {
            return true;
        } else {
            return false;
        }
    }

    bool RpcClient::AddAssociation(IN DWORD detection_id, IN DWORD associated, IN double strength) {
        protobuffer::DetectionAssociation request;
        request.set_detection_id(detection_id);
        request.set_associated_id(associated);
        request.set_strength(strength);

        protobuffer::ResponseMessage response;
        ClientContext context;

        Status status = stub_->AddAssociation(&context, request, &response);

        if(status.ok() && response.received()) {
            return true;
        } else {
            return false;
        }
    }

    bool RpcClient::UpdateCertainty(IN const std::shared_ptr<Detection>& detection) {
        protobuffer::DetectionCertaintyUpdate request;
        request.set_id(detection->dwID);
        request.set_raw_certainty(detection->info.GetIntrinsicCertainty());
        request.set_certainty(detection->info.GetCertainty());

        protobuffer::ResponseMessage response;
        ClientContext context;

        Status status = stub_->UpdateCertainty(&context, request, &response);

        if(status.ok() && response.received()) {
            return true;
        } else {
            return false;
        }
    }

    bool RpcClient::SendLogMessage(const std::wstring& msg, Log::Severity sev, Log::Detail det) {
        SYSTEMTIME st;
        GetSystemTime(&st);

        protobuffer::LogMessage request;
        request.set_client_id("TO_BE_SET_IN_THE_FUTURE");
        request.set_timestamp(SystemTimeToInteger(st));
        request.set_message(WidestringToString(msg));
        request.set_severity(static_cast<bluespawn::protobuffer::LogSeverity>(sev));
        request.set_detail(static_cast<bluespawn::protobuffer::LogDetail>(det));

        protobuffer::ResponseMessage response;
        ClientContext context;

        Status status = stub_->SendLogMessage(&context, request, &response);

        if(status.ok() && response.received()) {
            return true;
        } else {
            return false;
        }
    }
}   // namespace RpcClient
