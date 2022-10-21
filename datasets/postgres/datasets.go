package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/ultravioletrs/cocos/datasets"
	db "github.com/ultravioletrs/cocos/internal/db"
)

const (
	errDuplicate  = "unique_violation"
	errInvalid    = "invalid_text_representation"
	errTruncation = "string_data_right_truncation"
)

var _ datasets.DatasetRepository = (*datasetRepo)(nil)

type datasetRepo struct {
	db db.Database
}

// NewRepository returns a new Datasets repository implementation.
func NewRepository(db db.Database) datasets.DatasetRepository {
	return datasetRepo{
		db: db,
	}
}

func (repo datasetRepo) Save(ctx context.Context, dataset datasets.Dataset) (string, error) {
	q := `INSERT INTO datasets (id, owner, name, metadata, description, format, location, created_at, updated_at)
		  VALUES (:id, :owner, :name, :metadata, :description, :format, :location, :created_at, :updated_at) RETURNING id;`

	ds, err := fromDataset(dataset)
	if err != nil {
		return "", errors.Wrap(errors.ErrCreateEntity, err)
	}

	row, err := repo.db.NamedQueryContext(ctx, q, ds)
	if err != nil {
		pqErr, ok := err.(*pq.Error)
		if ok {
			switch pqErr.Code.Name() {
			case errInvalid, errTruncation:
				return "", errors.Wrap(errors.ErrMalformedEntity, err)
			case errDuplicate:
				return "", errors.Wrap(errors.ErrConflict, err)
			}
		}

		return "", errors.Wrap(errors.ErrCreateEntity, err)
	}
	defer row.Close()
	row.Next()
	var id string
	if err := row.Scan(&id); err != nil {
		return "", err
	}
	return id, nil
}

func (repo datasetRepo) RetrieveByID(ctx context.Context, owner, id string) (datasets.Dataset, error) {
	q := `SELECT id, name, owner, metadata, description, location, format, created_at, updated_at FROM datasets WHERE id = $1;`

	dbds := dbDataset{ID: id}

	if err := repo.db.QueryRowxContext(ctx, q, id).StructScan(&dbds); err != nil {
		pqErr, ok := err.(*pq.Error)
		if err == sql.ErrNoRows || ok && errInvalid == pqErr.Code.Name() {
			return datasets.Dataset{}, errors.Wrap(errors.ErrNotFound, err)
		}
		return datasets.Dataset{}, errors.Wrap(errors.ErrViewEntity, err)
	}

	return toDataset(dbds)
}

func (repo datasetRepo) RetrieveAll(ctx context.Context, owner string, pm datasets.PageMetadata) (datasets.Page, error) {
	nq, name := NameQuery(pm.Name)
	oq := OrderQuery(pm.Order)
	dq := DirQuery(pm.Dir)
	m, mq, err := MetadataQuery(pm.Metadata)
	if err != nil {
		return datasets.Page{}, errors.Wrap(errors.ErrViewEntity, err)
	}

	var query []string
	if mq != "" {
		query = append(query, mq)
	}
	if nq != "" {
		query = append(query, nq)
	}

	var whereClause string
	if len(query) > 0 {
		whereClause = fmt.Sprintf(" WHERE %s", strings.Join(query, " AND "))
	}

	q := `SELECT id, name, COALESCE(description, '') AS description, owner, created_at,
	updated_at, location, format, metadata
				FROM datasets %s
				ORDER BY %s %s LIMIT :limit OFFSET :offset`

	q = fmt.Sprintf(q, whereClause, oq, dq)
	params := map[string]interface{}{
		"owner":    owner,
		"limit":    pm.Limit,
		"offset":   pm.Offset,
		"name":     name,
		"metadata": m,
	}

	rows, err := repo.db.NamedQueryContext(ctx, q, params)
	if err != nil {
		return datasets.Page{}, errors.Wrap(errors.ErrViewEntity, err)
	}
	defer rows.Close()

	var items []datasets.Dataset
	for rows.Next() {
		dbd := dbDataset{Owner: owner}
		if err := rows.StructScan(&dbd); err != nil {
			return datasets.Page{}, errors.Wrap(errors.ErrViewEntity, err)
		}

		ds, err := toDataset(dbd)
		if err != nil {
			return datasets.Page{}, err
		}
		items = append(items, ds)
	}
	cq := fmt.Sprintf(`SELECT COUNT(*) FROM datasets %s;`, whereClause)

	total, err := repo.total(ctx, cq, params)
	if err != nil {
		return datasets.Page{}, errors.Wrap(errors.ErrViewEntity, err)
	}

	page := datasets.Page{
		Datasets: items,
		PageMetadata: datasets.PageMetadata{
			Total:  total,
			Offset: pm.Offset,
			Limit:  pm.Limit,
			Order:  pm.Order,
			Dir:    pm.Dir,
		},
	}
	return page, nil
}

func (repo datasetRepo) Update(ctx context.Context, d datasets.Dataset) error {
	q := `UPDATE datasets SET name = :name, metadata = :metadata, description = :description WHERE id = :id;`

	dbdts, err := toDBDataset(d)
	if err != nil {
		return errors.Wrap(errors.ErrUpdateEntity, err)
	}
	res, errdb := repo.db.NamedExecContext(ctx, q, dbdts)
	if errdb != nil {
		pqErr, ok := errdb.(*pq.Error)
		if ok {
			switch pqErr.Code.Name() {
			case errInvalid, errTruncation:
				return errors.Wrap(errors.ErrMalformedEntity, errdb)
			}
		}

		return errors.Wrap(errors.ErrUpdateEntity, errdb)
	}

	cnt, errdb := res.RowsAffected()
	if errdb != nil {
		return errors.Wrap(errors.ErrUpdateEntity, errdb)
	}

	if cnt == 0 {
		return errors.ErrNotFound
	}

	return nil
}

func (repo datasetRepo) Delete(ctx context.Context, id string) error {
	q := `DELETE FROM datasets WHERE id = :id`

	ds := dbDataset{
		ID: id,
	}

	if _, err := repo.db.NamedExecContext(ctx, q, ds); err != nil {
		if err == sql.ErrNoRows {
			return errors.Wrap(errors.ErrNotFound, err)

		}
		return errors.Wrap(errors.ErrViewEntity, err)
	}

	return nil
}

func (repo datasetRepo) total(ctx context.Context, query string, params interface{}) (uint64, error) {
	rows, err := repo.db.NamedQueryContext(ctx, query, params)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	total := uint64(0)
	if rows.Next() {
		if err := rows.Scan(&total); err != nil {
			return 0, err
		}
	}
	return total, nil
}

type dbDataset struct {
	ID          string    `db:"id"`
	Token       string    `db:"token"`
	Name        string    `db:"name"`
	Description string    `db:"description"`
	Owner       string    `db:"owner"`
	Size        uint64    `db:"size"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
	Location    string    `db:"location"`
	Format      string    `db:"format"`
	Metadata    []byte    `db:"metadata"`
	Path        string    `db:"path"`
}

func toDataset(d dbDataset) (datasets.Dataset, error) {
	var metadata map[string]interface{}
	if d.Metadata != nil {
		if err := json.Unmarshal([]byte(d.Metadata), &metadata); err != nil {
			return datasets.Dataset{}, errors.Wrap(errors.ErrMalformedEntity, err)
		}
	}
	ret := datasets.Dataset{
		ID:          d.ID,
		Token:       d.Token,
		Name:        d.Name,
		Description: d.Description,
		Owner:       d.Owner,
		Size:        d.Size,
		CreatedAt:   d.CreatedAt,
		UpdatedAt:   d.UpdatedAt,
		Location:    d.Location,
		Format:      d.Format,
		Metadata:    metadata,
		Path:        d.Path,
	}
	return ret, nil
}

func fromDataset(d datasets.Dataset) (dbDataset, error) {
	metadata := []byte("{}")
	if len(d.Metadata) > 0 {
		b, err := json.Marshal(d.Metadata)
		if err != nil {
			return dbDataset{}, errors.Wrap(errors.ErrMalformedEntity, err)
		}
		metadata = b
	}
	ret := dbDataset{
		ID:          d.ID,
		Token:       d.Token,
		Name:        d.Name,
		Description: d.Description,
		Owner:       d.Owner,
		Size:        d.Size,
		CreatedAt:   d.CreatedAt,
		UpdatedAt:   d.UpdatedAt,
		Location:    d.Location,
		Format:      d.Format,
		Metadata:    metadata,
		Path:        d.Path,
	}
	return ret, nil
}

func NameQuery(name string) (string, string) {
	if name == "" {
		return "", ""
	}
	name = fmt.Sprintf(`%%%s%%`, strings.ToLower(name))
	nq := `LOWER(name) LIKE :name`
	return nq, name
}

func OrderQuery(order string) string {
	switch order {
	case "name":
		return "name"
	default:
		return "id"
	}
}

func DirQuery(dir string) string {
	switch dir {
	case "asc":
		return "ASC"
	default:
		return "DESC"
	}
}

func MetadataQuery(m datasets.Metadata) ([]byte, string, error) {
	mq := ""
	mb := []byte("{}")
	if len(m) > 0 {
		mq = `metadata @> :metadata`

		b, err := json.Marshal(m)
		if err != nil {
			return nil, "", err
		}
		mb = b
	}
	return mb, mq, nil
}

func (repo datasetRepo) Remove(ctx context.Context, id string) error {
	dbth := dbDataset{
		ID: id,
	}
	q := `DELETE FROM datasets WHERE id = :id`
	if _, err := repo.db.NamedExecContext(ctx, q, dbth); err != nil {
		return errors.Wrap(errors.ErrRemoveEntity, err)
	}
	return nil
}

func toDBDataset(ds datasets.Dataset) (dbDataset, error) {
	data := []byte("{}")
	if len(ds.Metadata) > 0 {
		b, err := json.Marshal(ds.Metadata)
		if err != nil {
			return dbDataset{}, errors.Wrap(errors.ErrMalformedEntity, err)
		}
		data = b
	}

	return dbDataset{
		ID:          ds.ID,
		Owner:       ds.Owner,
		Name:        ds.Name,
		Description: ds.Description,
		Metadata:    data,
		Size:        ds.Size,
	}, nil
}
