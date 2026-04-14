package tc

// AttachmentMatchField identifies which packet field the current attachment
// rule matches in the u32 classifier.
type AttachmentMatchField string

const (
	AttachmentMatchSource      AttachmentMatchField = "source_ip"
	AttachmentMatchDestination AttachmentMatchField = "destination_ip"
)

func (f AttachmentMatchField) Valid() bool {
	switch f {
	case AttachmentMatchSource, AttachmentMatchDestination:
		return true
	default:
		return false
	}
}

func (f AttachmentMatchField) u32Token() string {
	switch f {
	case AttachmentMatchSource:
		return "src"
	case AttachmentMatchDestination:
		return "dst"
	default:
		return ""
	}
}

func attachmentMatchFieldForDirection(direction Direction) AttachmentMatchField {
	switch direction {
	case DirectionUpload:
		return AttachmentMatchSource
	case DirectionDownload:
		return AttachmentMatchDestination
	default:
		return ""
	}
}
